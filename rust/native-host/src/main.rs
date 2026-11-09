fn main() {
    let command = atomdns_native_host::parse_args(std::env::args_os());
    let result = match command {
        Ok(atomdns_native_host::CliCommand::Version) => {
            println!("{}", atomdns_native_host::build_identity::VERSION);
            return;
        }
        Ok(atomdns_native_host::CliCommand::Check { config, dir }) => {
            match atomdns_native_host::resolve_config_paths(&config, dir.as_deref())
                .map_err(|error| error.to_string())
                .and_then(|(config, root)| {
                    atomdns_native_host::check_config_in(&config, root.as_deref())
                        .map_err(|error| error.to_string())
                }) {
                Ok(report) => {
                    print!("{report}");
                    std::process::exit(report.exit_code());
                }
                Err(error) => Err(error),
            }
        }
        Ok(atomdns_native_host::CliCommand::Start { config, dir }) => {
            // Before anything can replace the executable on disk.
            atomdns_native_host::mark_image_start();
            atomdns_native_host::configure_process_memory();
            serve(&config, dir.as_deref())
        }
        Err(error) => Err(error.to_string()),
    };
    if let Err(error) = result {
        eprintln!("atomdns: {error}");
        atomdns_native_host::record_fatal(&error);
        std::process::exit(2);
    }
}

/// Runs the host until it is told to stop.
fn serve(config: &std::path::Path, dir: Option<&std::path::Path>) -> Result<(), String> {
    let (config_path, root) = atomdns_native_host::resolve_config_paths(config, dir)
        .map_err(|error| error.to_string())?;
    let assembly =
        atomdns_native_host::HostAssembly::from_config_file_in(&config_path, root.as_deref())
            .map_err(|error| error.to_string())?;
    assembly.run().map_err(|error| error.to_string())
}
