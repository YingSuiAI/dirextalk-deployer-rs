use clap::Parser;
use deployer_host::{
    BUNDLE_PATH, DigestHex, InstallOutcome, Installer, LinuxBackend, MAX_INSTALL_REQUEST_BYTES,
    MAX_RECEIPT_KEY_BYTES, MAX_RELEASE_BUNDLE_BYTES, RECEIPT_KEY_PATH, REQUEST_PATH,
    canonical_json, read_stable_regular,
};
use std::fs;
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "dirextalk-host-installer", disable_help_subcommand = true)]
struct Arguments {
    #[arg(long, value_parser = parse_digest)]
    request_sha256: DigestHex,
}

fn parse_digest(value: &str) -> Result<DigestHex, String> {
    DigestHex::parse(value).map_err(|error| error.to_string())
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let outcome = match load_inputs() {
        Ok(inputs) => Installer::new(LinuxBackend).install(
            &arguments.request_sha256,
            &inputs.request,
            &inputs.bundle,
            &inputs.key,
        ),
        Err(message) => InstallOutcome::Failure {
            error: deployer_host::InstallFailure {
                kind: deployer_host::FailureKind::Infrastructure,
                message,
            },
        },
    };
    if matches!(outcome, InstallOutcome::Success(_))
        && let Err(error) = fs::remove_file(RECEIPT_KEY_PATH)
    {
        eprintln!("infrastructure_failure: remove staged receipt key: {error}");
        return ExitCode::from(1);
    }
    match &outcome {
        InstallOutcome::Success(receipt) => print_json(receipt),
        InstallOutcome::WaitingUser { reason } => eprintln!("waiting_user: {reason}"),
        InstallOutcome::Failure { error } => eprintln!(
            "{}: {}",
            match error.kind {
                deployer_host::FailureKind::Contract => "contract_failure",
                deployer_host::FailureKind::Infrastructure => "infrastructure_failure",
            },
            error.message
        ),
    }
    ExitCode::from(outcome.exit_code())
}

struct StagedInputs {
    request: Vec<u8>,
    bundle: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
}

fn load_inputs() -> Result<StagedInputs, String> {
    let request = read_stable_regular(
        std::path::Path::new(REQUEST_PATH),
        None,
        Some(0o600),
        MAX_INSTALL_REQUEST_BYTES,
    )
    .map_err(|error| format!("read request: {error}"))?;
    let bundle = read_stable_regular(
        std::path::Path::new(BUNDLE_PATH),
        None,
        Some(0o600),
        MAX_RELEASE_BUNDLE_BYTES,
    )
    .map_err(|error| format!("read bundle: {error}"))?;
    let key = Zeroizing::new(
        read_stable_regular(
            std::path::Path::new(RECEIPT_KEY_PATH),
            None,
            Some(0o600),
            MAX_RECEIPT_KEY_BYTES,
        )
        .map_err(|error| format!("read receipt key: {error}"))?,
    );
    Ok(StagedInputs {
        request,
        bundle,
        key,
    })
}

fn print_json<T: serde::Serialize>(value: &T) {
    match canonical_json(value) {
        Ok(bytes) => println!("{}", String::from_utf8_lossy(&bytes)),
        Err(error) => eprintln!("receipt serialization failed: {error}"),
    }
}
