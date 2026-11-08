//! The proxy side of the rule table owner (atom `docs/design.md` §5, §6,
//! §8): the proxy state and the transaction that applies a change to
//! sing-box before saving it.
//!
//! A transaction: validate the next rules and proxy state → generate the
//! sing-box configuration → if it differs from the running one, apply it
//! (check, write, reload, confirm; rollback on failure) → write the atom
//! files → publish. While it runs every other change of this owner is
//! refused with 409 (writes do not queue), and only one application runs in
//! the process. A configuration that would come out the same (a rename) is
//! not applied again.

use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use super::{AtomRules, Refusal, Rule, State, ip_rules, now};
use crate::atom_proxy::{self, FINAL, ProxyState};
use crate::atom_singbox::{self as sb, ApplyError, ApplyGuard, Host};

pub(crate) struct Proxy {
    pub(super) host: Host,
    pub(super) state: std::cell::RefCell<ProxyState>,
    /// The resolver when the settings name none: from AtomDNS's domestic
    /// upstreams, set after the configuration compiled.
    pub(super) default_resolver: std::cell::RefCell<String>,
}

impl Proxy {
    pub(super) fn load(root: &std::path::Path, host: Host) -> Result<Self, String> {
        let state = if root.as_os_str().is_empty() {
            ProxyState::default()
        } else {
            atom_proxy::load(root, &host.reserved_ports())?
        };
        Ok(Self {
            host,
            state: std::cell::RefCell::new(state),
            default_resolver: std::cell::RefCell::new(sb::FALLBACK_RESOLVER.to_owned()),
        })
    }
}

/// The outcome of the latest application (process-wide: it outlives
/// configuration reloads).
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ApplyRecord {
    pub(crate) at: i64,
    /// What asked for it: `nodes`, `groups`, `final`, `settings`, `rules`,
    /// `apply` (the API), `startup` (a configuration started serving).
    pub(crate) trigger: String,
    pub(crate) ok: bool,
    /// Whether sing-box got a new configuration (false: already current).
    pub(crate) changed: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) error: String,
}

static LAST_APPLY: Mutex<Option<ApplyRecord>> = Mutex::new(None);

pub(crate) fn last_apply() -> Option<ApplyRecord> {
    LAST_APPLY.lock().ok().and_then(|record| record.clone())
}

fn record(trigger: &str, changed: bool, error: Option<String>) {
    if let Ok(mut last) = LAST_APPLY.lock() {
        *last = Some(ApplyRecord {
            at: now(),
            trigger: trigger.to_owned(),
            ok: error.is_none(),
            changed,
            error: error.unwrap_or_default(),
        });
    }
}

pub(super) fn busy() -> Refusal {
    Refusal::new(409, "另一个修改正在应用到 sing-box，请稍后再试")
}

fn unconfigured() -> Refusal {
    Refusal::new(404, "没有配置 sing-box（atom_rules 的 singbox 段）")
}

fn apply_refusal(error: ApplyError) -> Refusal {
    match error {
        ApplyError::Check(message) => {
            Refusal::new(400, format!("sing-box check 不通过，没有应用: {message}"))
        }
        ApplyError::Runtime(message) => {
            Refusal::new(502, format!("应用到 sing-box 失败: {message}"))
        }
    }
}

/// Runs a blocking application with the process-wide guard, recording the
/// outcome inside the blocking task (it completes even if the caller is
/// dropped).
async fn run_apply(
    guard: ApplyGuard,
    host: Host,
    bytes: Vec<u8>,
    secret: String,
    trigger: String,
) -> Result<(), ApplyError> {
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let result = sb::apply_blocking(&host, &bytes, &secret);
        record(
            &trigger,
            true,
            result.as_ref().err().map(ToString::to_string),
        );
        result
    })
    .await
    .unwrap_or_else(|error| Err(ApplyError::Runtime(format!("应用任务异常结束: {error}"))))
}

impl AtomRules {
    pub(crate) fn proxy_state(&self) -> Option<ProxyState> {
        self.proxy
            .as_ref()
            .map(|proxy| proxy.state.borrow().clone())
    }

    pub(crate) fn proxy_host(&self) -> Option<&Host> {
        self.proxy.as_ref().map(|proxy| &proxy.host)
    }

    /// Takes the default resolver from AtomDNS's effective upstreams.
    pub(crate) fn set_default_resolver(
        &self,
        upstreams: &std::collections::BTreeMap<String, Vec<crate::config::settings::UpstreamEntry>>,
    ) {
        if let Some(proxy) = &self.proxy {
            let found = upstreams
                .get(&proxy.host.resolver_group)
                .and_then(|entries| sb::default_resolver(entries));
            *proxy.default_resolver.borrow_mut() =
                found.unwrap_or_else(|| sb::FALLBACK_RESOLVER.to_owned());
        }
    }

    /// The resolver sing-box uses with `state`'s settings.
    pub(crate) fn resolver_for(&self, state: &ProxyState) -> String {
        let configured = state.settings.resolver.trim();
        match &self.proxy {
            _ if !configured.is_empty() => configured.to_owned(),
            Some(proxy) => proxy.default_resolver.borrow().clone(),
            None => sb::FALLBACK_RESOLVER.to_owned(),
        }
    }

    fn generate(
        &self,
        host: &Host,
        state: &ProxyState,
        rules: &[Rule],
        secret: &str,
    ) -> Result<Vec<u8>, Refusal> {
        sb::generate(
            host,
            state,
            &ip_rules(rules),
            &self.resolver_for(state),
            secret,
        )
        .map_err(|message| Refusal::new(500, format!("生成 sing-box 配置失败: {message}")))
    }

    /// Whether the running file is what the current state generates.
    pub(crate) fn in_sync(&self) -> Option<bool> {
        let proxy = self.proxy.as_ref()?;
        let live = sb::read_live(&proxy.host)?;
        let secret = sb::secret_of(&live)?;
        let state = proxy.state.borrow().clone();
        let rules = self.state.borrow().rules.clone();
        Some(
            self.generate(&proxy.host, &state, &rules, &secret)
                .is_ok_and(|bytes| bytes == live),
        )
    }

    /// The secret of the running configuration.
    pub(crate) fn live_secret(&self) -> Option<String> {
        let proxy = self.proxy.as_ref()?;
        sb::read_live(&proxy.host)
            .as_deref()
            .and_then(sb::secret_of)
    }

    pub(crate) fn check_proxy_version(&self, version: Option<u64>) -> Result<(), Refusal> {
        let proxy = self.proxy.as_ref().ok_or_else(unconfigured)?;
        let current = proxy.state.borrow().version;
        match version {
            Some(version) if version != current => Err(Refusal {
                version: Some(current),
                ..Refusal::new(
                    409,
                    format!(
                        "节点配置已被修改（当前版本 {current}，请求的版本 {version}），请刷新后重试"
                    ),
                )
            }),
            _ => Ok(()),
        }
    }

    /// Commits a rules change: through sing-box when its IP rules differ.
    pub(crate) async fn commit_rules(&self, next: State) -> Result<(), Refusal> {
        if self.proxy.is_none() || ip_rules(&next.rules) == ip_rules(&self.state.borrow().rules) {
            return self.commit(next, true, false);
        }
        self.transact(Some(next), None, "rules").await
    }

    /// Applies and saves the next rules (`rules`) and proxy state (`proxy`);
    /// `None` keeps the current one.
    pub(crate) async fn transact(
        &self,
        rules: Option<State>,
        proxy: Option<ProxyState>,
        trigger: &str,
    ) -> Result<(), Refusal> {
        let owner = self.proxy.as_ref().ok_or_else(unconfigured)?;
        if self.busy.get() {
            return Err(busy());
        }
        let next_rules = rules.clone().unwrap_or_else(|| self.state.borrow().clone());
        let next_proxy = proxy
            .clone()
            .unwrap_or_else(|| owner.state.borrow().clone());
        next_proxy.validate(&owner.host.reserved_ports())?;
        self.compile(&next_rules, Some(&next_proxy))?;
        let in_memory = self.root.as_os_str().is_empty();
        let host = owner.host.clone();
        let live = sb::read_live(&host);
        let unchanged = match live.as_deref().and_then(sb::secret_of) {
            Some(secret) => {
                live.as_deref()
                    == Some(
                        self.generate(&host, &next_proxy, &next_rules.rules, &secret)?
                            .as_slice(),
                    )
            }
            None => false,
        };
        let applied = !in_memory && !unchanged;
        if applied {
            let guard = ApplyGuard::try_begin().ok_or_else(busy)?;
            let secret = sb::new_secret();
            let bytes = self.generate(&host, &next_proxy, &next_rules.rules, &secret)?;
            self.busy.set(true);
            let result = run_apply(guard, host.clone(), bytes, secret, trigger.to_owned()).await;
            self.busy.set(false);
            result.map_err(apply_refusal)?;
        }
        if !in_memory {
            let old_proxy = owner.state.borrow().clone();
            let saved = (|| {
                if proxy.is_some() {
                    atom_proxy::save(&self.root, &next_proxy)?;
                }
                if rules.is_some() {
                    if let Err(error) = self.write_rules_file(&next_rules) {
                        if proxy.is_some() {
                            let _ = atom_proxy::save(&self.root, &old_proxy);
                        }
                        return Err(error);
                    }
                }
                Ok::<(), std::io::Error>(())
            })();
            if let Err(error) = saved {
                let restored = if applied {
                    let old = live.clone();
                    tokio::task::spawn_blocking(move || sb::rollback(&host, old.as_deref()))
                        .await
                        .unwrap_or_else(|error| format!("回滚任务异常结束: {error}"))
                } else {
                    "sing-box 配置没有变".to_owned()
                };
                record(
                    trigger,
                    applied,
                    Some(format!("保存失败: {error}；{restored}")),
                );
                return Err(Refusal::new(500, format!("保存失败: {error}；{restored}")));
            }
        }
        if !applied {
            record(trigger, false, None);
        }
        if let Some(next) = proxy {
            *owner.state.borrow_mut() = next;
        }
        if let Some(next) = rules {
            // Rulesets may have changed meanwhile (a download): keep theirs.
            let mut current = self.state.borrow().clone();
            current.version = next.version;
            current.rules = next.rules;
            let proxy_state = self.proxy_state();
            let table = self.compile(&current, proxy_state.as_ref())?;
            *self.state.borrow_mut() = current;
            self.table.replace(std::rc::Rc::new(table));
        }
        Ok(())
    }

    /// Deletes a group. Rules that proxy to it block the deletion (409 with
    /// their IDs) unless `confirm`: they are moved to Final. Other groups
    /// and Final drop it.
    pub(crate) async fn delete_group(&self, id: &str, confirm: bool) -> Result<u64, Refusal> {
        let owner = self.proxy.as_ref().ok_or_else(unconfigured)?;
        let mut next = owner.state.borrow().clone();
        next.remove_group(id)?;
        next.version += 1;
        let users: Vec<String> = self
            .state
            .borrow()
            .rules
            .iter()
            .filter(
                |rule| matches!(&rule.action, super::Action::Proxy { group_id } if group_id == id),
            )
            .map(|rule| rule.id.clone())
            .collect();
        let rules = if users.is_empty() {
            None
        } else if !confirm {
            return Err(Refusal {
                rules: users,
                ..Refusal::new(
                    409,
                    format!(
                        "节点组 `{id}` 还被规则引用；确认删除（confirm=true）后这些规则改用 Final"
                    ),
                )
            });
        } else {
            let mut rules = self.state.borrow().clone();
            for rule in &mut rules.rules {
                if matches!(&rule.action, super::Action::Proxy { group_id } if group_id == id) {
                    rule.action = super::Action::Proxy {
                        group_id: FINAL.to_owned(),
                    };
                }
            }
            rules.version += 1;
            Some(rules)
        };
        let version = next.version;
        self.transact(rules, Some(next), "groups").await?;
        Ok(version)
    }

    /// Switches a selector group or Final at runtime (Clash API), records
    /// the choice, and keeps the running file in step (same secret, no
    /// reload) when it was current.
    pub(crate) async fn select(
        &self,
        id: &str,
        member: &str,
        version: Option<u64>,
    ) -> Result<u64, Refusal> {
        let owner = self.proxy.as_ref().ok_or_else(unconfigured)?;
        if self.busy.get() {
            return Err(busy());
        }
        self.check_proxy_version(version)?;
        let mut next = owner.state.borrow().clone();
        next.select(id, member)?;
        next.version += 1;
        if !self.root.as_os_str().is_empty() {
            let host = owner.host.clone();
            let live = sb::read_live(&host)
                .ok_or_else(|| Refusal::new(409, "sing-box 还没有应用过配置"))?;
            let secret = sb::secret_of(&live)
                .ok_or_else(|| Refusal::new(409, "sing-box 配置里没有 Clash API 密钥"))?;
            let rules = self.state.borrow().rules.clone();
            let current = owner.state.borrow().clone();
            let in_step = self.generate(&host, &current, &rules, &secret)? == live;
            let file = if in_step {
                Some(self.generate(&host, &next, &rules, &secret)?)
            } else {
                None
            };
            let guard = ApplyGuard::try_begin().ok_or_else(busy)?;
            let (tag, member) = (id.to_owned(), member.to_owned());
            self.busy.set(true);
            let result = tokio::task::spawn_blocking(move || {
                let _guard = guard;
                sb::select(&host, &secret, &tag, &member)?;
                if let Some(bytes) = file {
                    crate::runtime_snapshot::write_durably(&host.config_path(), &bytes)
                        .map_err(|error| format!("已切换，但更新配置文件失败: {error}"))?;
                }
                Ok::<(), String>(())
            })
            .await
            .unwrap_or_else(|error| Err(format!("切换任务异常结束: {error}")));
            self.busy.set(false);
            result.map_err(|message| Refusal::new(502, message))?;
            atom_proxy::save(&self.root, &next)
                .map_err(|error| Refusal::new(500, format!("已切换，但保存失败: {error}")))?;
        }
        let version = next.version;
        *owner.state.borrow_mut() = next;
        Ok(version)
    }

    /// Tests every member of a group or Final through the Clash API.
    pub(crate) async fn delay(
        &self,
        id: &str,
        url: Option<String>,
        timeout_ms: u32,
    ) -> Result<Value, Refusal> {
        let owner = self.proxy.as_ref().ok_or_else(unconfigured)?;
        let url = {
            let state = owner.state.borrow();
            if id != FINAL && state.group(id).is_none() {
                return Err(Refusal::new(404, format!("节点组 `{id}` 不存在")));
            }
            url.or_else(|| state.group(id).and_then(|group| group.url.clone()))
                .unwrap_or_else(|| atom_proxy::DEFAULT_URL.to_owned())
        };
        let secret = self
            .live_secret()
            .ok_or_else(|| Refusal::new(409, "sing-box 还没有应用过配置"))?;
        let host = owner.host.clone();
        let tag = id.to_owned();
        tokio::task::spawn_blocking(move || sb::delay(&host, &secret, &tag, &url, timeout_ms))
            .await
            .unwrap_or_else(|error| Err(format!("测速任务异常结束: {error}")))
            .map_err(|message| Refusal::new(502, message))
    }

    /// Applies the current state again with a new secret (`POST apply`).
    pub(crate) async fn reapply(&self) -> Result<(), Refusal> {
        let owner = self.proxy.as_ref().ok_or_else(unconfigured)?;
        if self.busy.get() {
            return Err(busy());
        }
        if self.root.as_os_str().is_empty() {
            return Ok(());
        }
        let guard = ApplyGuard::try_begin().ok_or_else(busy)?;
        let secret = sb::new_secret();
        let state = owner.state.borrow().clone();
        let rules = self.state.borrow().rules.clone();
        let bytes = self.generate(&owner.host, &state, &rules, &secret)?;
        self.busy.set(true);
        let result = run_apply(guard, owner.host.clone(), bytes, secret, "apply".to_owned()).await;
        self.busy.set(false);
        result.map_err(apply_refusal)
    }

    /// When a configuration starts serving: bring sing-box to what this
    /// state generates if it differs (first start, upgrade, an upstream
    /// change of the default resolver). Failures are logged and recorded.
    pub(crate) async fn ensure(self: std::rc::Rc<Self>) {
        let Some(owner) = &self.proxy else {
            return;
        };
        if self.root.as_os_str().is_empty() {
            return;
        }
        for _ in 0..240 {
            if !ApplyGuard::busy() && !self.busy.get() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if self.in_sync() == Some(true) {
            record("startup", false, None);
            return;
        }
        let Some(guard) = ApplyGuard::try_begin() else {
            crate::diag::warn_line!(
                "atom sing-box: another application is running; startup check skipped"
            );
            return;
        };
        let secret = sb::new_secret();
        let state = owner.state.borrow().clone();
        let rules = self.state.borrow().rules.clone();
        let bytes = match self.generate(&owner.host, &state, &rules, &secret) {
            Ok(bytes) => bytes,
            Err(refusal) => {
                record("startup", false, Some(refusal.message.clone()));
                return;
            }
        };
        self.busy.set(true);
        let result = run_apply(
            guard,
            owner.host.clone(),
            bytes,
            secret,
            "startup".to_owned(),
        )
        .await;
        self.busy.set(false);
        if let Err(error) = result {
            crate::diag::warn_line!(
                "atom sing-box: applying the configuration at startup failed: {error}"
            );
        }
    }

    /// Starts the startup check when this configuration starts serving.
    pub(crate) fn start(self: &std::rc::Rc<Self>) {
        if self.proxy.is_some() && !self.root.as_os_str().is_empty() {
            tokio::task::spawn_local(std::rc::Rc::clone(self).ensure());
        }
    }
}
