//! atom fork: the rule-source catalog (atom step 6b).
//!
//! Public rule repositories a rule can use without creating a ruleset first:
//! MetaCubeX's `meta-rules-dat` (`sing` branch: `geo/geosite/<name>.srs`
//! names, `geo/geoip/<name>.srs` IP prefixes) and blackmatrix7's
//! `ios_rule_script` (`rule/Clash/<name>/<name>.list`, names and prefixes in
//! one file). An entry's ID is `meta:<name>` or `bm7:<name>`; a rule that
//! names one gets a managed ruleset of that ID (source `catalog`),
//! downloaded at once and removed when no rule names it any more.
//!
//! The index ships with the configuration (`rule/atom_catalog.json`) and is
//! refreshed from GitHub's API through `main_proxy` (`POST catalog/sync`,
//! and daily) into `webinfo/atom_catalog.json`, which wins when newer.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The index the configuration ships.
pub(crate) const SNAPSHOT: &str = "rule/atom_catalog.json";
/// The index the last sync wrote.
pub(crate) const SYNCED: &str = "webinfo/atom_catalog.json";

const META_RAW: &str = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo";
const BM7_RAW: &str = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash";
const META_TREES: &str = "https://api.github.com/repos/MetaCubeX/meta-rules-dat/git/trees/sing:geo";
const BM7_TREE: &str =
    "https://api.github.com/repos/blackmatrix7/ios_rule_script/git/trees/master:rule/Clash";
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
const SYNC_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Meta {
    #[serde(default)]
    pub(crate) geosite: Vec<String>,
    #[serde(default)]
    pub(crate) geoip: Vec<String>,
}

/// The index: Unix seconds it was made, and the names of each repository.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Catalog {
    #[serde(default)]
    pub(crate) updated_at: i64,
    #[serde(default)]
    pub(crate) meta: Meta,
    #[serde(default)]
    pub(crate) bm7: Vec<String>,
}

/// One entry as rules and the UI see it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) id: String,
    pub(crate) provider: &'static str,
    pub(crate) name: String,
    /// Whether it has names (meta: a geosite file); bm7: unknown (null)
    /// until downloaded.
    pub(crate) names: Option<bool>,
    /// Whether it has IP prefixes (meta: a geoip file); bm7: unknown.
    pub(crate) ips: Option<bool>,
}

/// A name as it may appear in a file path of the repository.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains(['/', '\\', '?', '#', '%'])
        && !name.starts_with('.')
        && name.chars().all(|c| !c.is_control() && !c.is_whitespace())
}

impl Catalog {
    fn read(path: &Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// The newer of the synced index and the shipped one (empty without
    /// either).
    pub(crate) fn load(root: &Path) -> Self {
        if root.as_os_str().is_empty() {
            return Self::default();
        }
        let shipped = Self::read(&root.join(SNAPSHOT));
        let synced = Self::read(&root.join(SYNCED));
        match (shipped, synced) {
            (Some(a), Some(b)) => {
                if b.updated_at >= a.updated_at {
                    b
                } else {
                    a
                }
            }
            (a, b) => a.or(b).unwrap_or_default(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        let meta_only_ip = self
            .meta
            .geoip
            .iter()
            .filter(|name| !self.meta.geosite.contains(name))
            .count();
        self.meta.geosite.len() + meta_only_ip + self.bm7.len()
    }

    /// Every entry: MetaCubeX names (geosite, then those only in geoip),
    /// then blackmatrix7.
    pub(crate) fn entries(&self) -> Vec<Entry> {
        let mut out = Vec::with_capacity(self.len());
        for name in &self.meta.geosite {
            out.push(Entry {
                id: format!("meta:{name}"),
                provider: "meta",
                name: name.clone(),
                names: Some(true),
                ips: Some(self.meta.geoip.contains(name)),
            });
        }
        for name in self.meta.geoip.iter().filter(|n| !self.meta.geosite.contains(n)) {
            out.push(Entry {
                id: format!("meta:{name}"),
                provider: "meta",
                name: name.clone(),
                names: Some(false),
                ips: Some(true),
            });
        }
        for name in &self.bm7 {
            out.push(Entry {
                id: format!("bm7:{name}"),
                provider: "bm7",
                name: name.clone(),
                names: None,
                ips: None,
            });
        }
        out
    }

    pub(crate) fn find(&self, id: &str) -> Option<Entry> {
        let (provider, name) = id.split_once(':')?;
        match provider {
            "meta" => {
                let names = self.meta.geosite.iter().any(|n| n == name);
                let ips = self.meta.geoip.iter().any(|n| n == name);
                (names || ips).then(|| Entry {
                    id: id.to_owned(),
                    provider: "meta",
                    name: name.to_owned(),
                    names: Some(names),
                    ips: Some(ips),
                })
            }
            "bm7" => self.bm7.iter().any(|n| n == name).then(|| Entry {
                id: id.to_owned(),
                provider: "bm7",
                name: name.to_owned(),
                names: None,
                ips: None,
            }),
            _ => None,
        }
    }
}

/// Whether `id` has the form of a catalog ID (`meta:` or `bm7:`).
pub(crate) fn is_catalog_id(id: &str) -> bool {
    id.split_once(':')
        .is_some_and(|(provider, name)| matches!(provider, "meta" | "bm7") && plain(name))
}

/// The files of an entry, with the format each one is read as.
pub(crate) fn urls(entry: &Entry) -> Vec<(String, &'static str)> {
    match entry.provider {
        "meta" => {
            let mut out = Vec::new();
            if entry.names != Some(false) {
                out.push((format!("{META_RAW}/geosite/{}.srs", entry.name), "srs"));
            }
            if entry.ips == Some(true) {
                out.push((format!("{META_RAW}/geoip/{}.srs", entry.name), "srs"));
            }
            out
        }
        _ => vec![(
            format!("{BM7_RAW}/{0}/{0}.list", entry.name),
            "text",
        )],
    }
}

#[derive(Deserialize)]
struct Tree {
    #[serde(default)]
    truncated: bool,
    tree: Vec<TreeEntry>,
}

#[derive(Deserialize)]
struct TreeEntry {
    path: String,
    #[serde(rename = "type")]
    kind: String,
}

async fn tree(url: &str, socks5: &str) -> Result<Tree, String> {
    let shutdown = atomdns_upstream_core::TransportCancellation::new();
    let bytes = crate::rule_download::fetch(
        crate::rule_download::Fetch {
            url,
            socks5,
            timeout: SYNC_TIMEOUT,
            max_bytes: SYNC_LIMIT,
            roots: None,
        },
        &shutdown,
    )
    .await
    .map_err(|e| format!("{url}: {e}"))?;
    let tree: Tree = serde_json::from_slice(&bytes).map_err(|e| format!("{url}: {e}"))?;
    if tree.truncated {
        return Err(format!("{url}: GitHub 返回的目录被截断"));
    }
    Ok(tree)
}

fn files(tree: &Tree, extension: &str) -> Vec<String> {
    let mut names: Vec<String> = tree
        .tree
        .iter()
        .filter(|e| e.kind == "blob")
        .filter_map(|e| e.path.strip_suffix(extension))
        .filter(|name| plain(name))
        .map(str::to_owned)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Reads the three directories from GitHub's API (through `socks5`) and
/// writes the synced index. Nothing is written unless all three answered.
pub(crate) async fn sync(root: &Path, socks5: &str, now: i64) -> Result<Catalog, String> {
    // Unit tests do not reach GitHub (the OpenAPI test calls every route).
    if cfg!(test) {
        return Err("单元测试不访问 GitHub".to_owned());
    }
    let geosite = tree(&format!("{META_TREES}/geosite"), socks5).await?;
    let geoip = tree(&format!("{META_TREES}/geoip"), socks5).await?;
    let bm7 = tree(BM7_TREE, socks5).await?;
    let mut bm7_names: Vec<String> = bm7
        .tree
        .iter()
        .filter(|e| e.kind == "tree" && plain(&e.path))
        .map(|e| e.path.clone())
        .collect();
    bm7_names.sort();
    let catalog = Catalog {
        updated_at: now,
        meta: Meta {
            geosite: files(&geosite, ".srs"),
            geoip: files(&geoip, ".srs"),
        },
        bm7: bm7_names,
    };
    if catalog.meta.geosite.is_empty() || catalog.bm7.is_empty() {
        return Err("GitHub 返回的目录是空的，保留原来的目录".to_owned());
    }
    if !root.as_os_str().is_empty() {
        let mut bytes = serde_json::to_vec(&catalog).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        crate::runtime_snapshot::write_durably(&root.join(SYNCED), &bytes)
            .map_err(|e| format!("保存目录失败: {e}"))?;
    }
    Ok(catalog)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Catalog {
        Catalog {
            updated_at: 10,
            meta: Meta {
                geosite: vec!["netflix".into(), "cn".into()],
                geoip: vec!["netflix".into(), "private".into()],
            },
            bm7: vec!["Telegram".into()],
        }
    }

    #[test]
    fn entries_ids_and_files() {
        let catalog = sample();
        assert_eq!(catalog.len(), 4);
        let ids: Vec<String> = catalog.entries().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, ["meta:netflix", "meta:cn", "meta:private", "bm7:Telegram"]);
        let netflix = catalog.find("meta:netflix").unwrap();
        assert_eq!((netflix.names, netflix.ips), (Some(true), Some(true)));
        assert_eq!(urls(&netflix).len(), 2);
        let private = catalog.find("meta:private").unwrap();
        assert_eq!(urls(&private), vec![(format!("{META_RAW}/geoip/private.srs"), "srs")]);
        assert_eq!(
            urls(&catalog.find("bm7:Telegram").unwrap()),
            vec![(format!("{BM7_RAW}/Telegram/Telegram.list"), "text")]
        );
        assert!(catalog.find("bm7:Netflix").is_none());
        assert!(catalog.find("other:x").is_none());
        assert!(is_catalog_id("meta:geolocation-!cn"));
        assert!(!is_catalog_id("meta:../x") && !is_catalog_id("rs-1234") && !is_catalog_id("meta:"));
    }

    #[test]
    fn the_newer_index_wins() {
        let root = std::env::temp_dir().join(format!("atom-catalog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("rule")).unwrap();
        std::fs::create_dir_all(root.join("webinfo")).unwrap();
        assert_eq!(Catalog::load(&root), Catalog::default());
        std::fs::write(root.join(SNAPSHOT), serde_json::to_vec(&sample()).unwrap()).unwrap();
        assert_eq!(Catalog::load(&root).updated_at, 10);
        let newer = Catalog { updated_at: 20, bm7: vec!["X".into()], ..Catalog::default() };
        std::fs::write(root.join(SYNCED), serde_json::to_vec(&newer).unwrap()).unwrap();
        assert_eq!(Catalog::load(&root), newer);
        let older = Catalog { updated_at: 5, ..Catalog::default() };
        std::fs::write(root.join(SYNCED), serde_json::to_vec(&older).unwrap()).unwrap();
        assert_eq!(Catalog::load(&root).updated_at, 10);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_shipped_snapshot_loads() {
        let text = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/rule/atom_catalog.json"));
        let catalog: Catalog = serde_json::from_str(text).unwrap();
        assert!(catalog.meta.geosite.len() > 1000 && catalog.bm7.len() > 500);
        assert!(catalog.find("meta:netflix").is_some_and(|e| e.ips == Some(true)));
        assert!(catalog.find("bm7:Telegram").is_some());
    }
}
