#![deny(unsafe_code)]
#![allow(clippy::pedantic)]

mod api;
mod assembly;
mod atom_catalog;
mod atom_dns_api;
mod atom_dryrun;
mod atom_ledger;
mod atom_links;
mod atom_proxy;
mod atom_proxy_api;
mod atom_rules;
mod atom_rules_api;
mod atom_singbox;
mod atom_system;
mod bind;
pub mod build_identity;
mod cache;
mod cache_dump;
mod cache_placement;
mod capture;
mod cli;
mod compile_thread;
mod config;
mod diag;
mod domain_output;
mod ecs;
mod edns_directive;
mod execution;
mod external_ui;
mod local_time;
mod local_url;
mod managed;
mod matchers;
mod memory;
mod observer;
mod plugins;
mod policy;
mod process_metrics;
mod requery;
mod rewrite;
mod route_learner;
mod rule_binary;
mod rule_download;
mod rule_formats;
mod rule_sources;
mod runtime_snapshot;
#[doc(hidden)]
pub mod settings_migrate;
mod special_groups;
mod static_ui;
mod tcp;
mod transaction;
mod udp;
mod udp_response;
#[cfg(test)]
mod udp_truncation_tests;
mod ui_manifest;
mod upstream_metrics;
mod webinfo;

pub use api::{ApiServer, ApiServerError};
pub use assembly::{
    AssemblyError, BoundHost, DnsServer, ForwardAdapter, HostAssembly, HostOptions, HostRunError,
    HostRuntime,
};
pub use cache::{
    CacheAdapterError, CacheCatalog, CacheClock, CacheTestClock, NativeCacheAdapter, PendingStore,
};
pub use cli::{CliCommand, CliError, parse_args, resolve_config_paths};
pub use config::{
    ApiConfig, CacheId, CacheKind, CachePluginConfig, CheckFinding, CheckFindingKind, CheckReport,
    CompiledConfig, ConfigError, DomainMapperConfig, DomainSetConfig, ForwardConfig,
    ForwardDefinitionConfig, ForwardEntryConfig, ForwardInvocationConfig, ForwardScheme,
    ForwardTargetConfig, ListenerConfig, ListenerKind, LogLevel, MapperOutcome,
    ResponseIpRuleConfig, SequenceConfig, check_config, check_config_in, compile_yaml,
    compile_yaml_with_base, compile_yaml_with_roots, load_and_compile, load_yaml,
};
pub use diag::record_fatal;
pub use managed::{ManagedDomainSet, PersistFault, PersistGate};
pub use memory::configure_process_memory;
pub use observer::{
    AdmissionError, AnswerDetailsStatus, AuditAnswer, AuditClock, AuditRecord, AuditSnapshot,
    AuditTestClock, CacheStatus, DurationHistogramBucket, DurationHistogramSnapshot,
    FailureProvenance, LocalFailureKind, MetricsSnapshot, QueryTerminalOutcome, QueryTransport,
    ResponseDetails, ResponseFlags, ResponseSource, ResponseState, UpstreamAttemptMetricsSnapshot,
    UpstreamAttemptOutcome, UpstreamAttemptRecord, UpstreamDiagnosticAttempt,
    UpstreamDiagnosticSelected, UpstreamDiagnostics, UpstreamTransport,
};
pub use process_metrics::mark_image_start;

pub use tcp::{TcpServer, TcpServerError};
pub use udp::{UdpServer, UdpServerError};

/// Parses and prepares a native host without opening a listener or an
/// upstream socket.
pub fn prepare_from_args<I, S>(args: I) -> Result<HostAssembly, HostError>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let command = parse_args(args).map_err(HostError::Cli)?;
    match command {
        CliCommand::Version => Err(HostError::Cli(CliError::new(
            "version does not prepare a host",
        ))),
        CliCommand::Check { .. } => Err(HostError::Cli(CliError::new(
            "check does not prepare a host",
        ))),
        CliCommand::Start { config, dir } => {
            let (config, root) =
                resolve_config_paths(&config, dir.as_deref()).map_err(HostError::Cli)?;
            HostAssembly::from_config_file_in(&config, root.as_deref()).map_err(HostError::Assembly)
        }
    }
}

/// Top-level preparation errors returned by the small CLI entrypoint.
#[derive(Debug)]
pub enum HostError {
    Cli(CliError),
    Config(ConfigError),
    Assembly(AssemblyError),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cli(error) => error.fmt(formatter),
            Self::Config(error) => error.fmt(formatter),
            Self::Assembly(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for HostError {}

pub use policy::{
    DomainPayload, HostAddresses, IpListHandle, IpSetConfig, POLICY_BYTES_LIMIT, POLICY_LINE_LIMIT,
    POLICY_RULE_LIMIT, ResponsePolicy, ResponsePolicyConfig, TtlPolicy,
};

pub use rule_sources::{RuleSources, RuleTiming};
pub use runtime_snapshot::{PreparedSnapshot, RuntimeControl};
