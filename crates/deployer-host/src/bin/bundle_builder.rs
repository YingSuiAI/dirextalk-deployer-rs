use clap::Parser;
use deployer_host::{
    BundleAssets, BundleBuildRequest, DigestHex, MAX_INSTALL_REQUEST_BYTES,
    MAX_RELEASE_BUNDLE_BYTES, build_bundle, canonical_json, parse_canonical_json,
    read_stable_regular,
};
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

const SIGNING_SEED_FILE_ENV: &str = "DIREXTALK_BUNDLE_SIGNING_SEED_FILE";
const MAX_RUNTIME_TEMPLATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_UPDATER_ASSET_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "dirextalk-bundle-builder",
    disable_help_subcommand = true,
    after_help = "Reads a canonical schema-1 JSON request. The raw 32-byte Ed25519 seed is read only from the 0600 regular file named by DIREXTALK_BUNDLE_SIGNING_SEED_FILE."
)]
struct Arguments {
    #[arg(long)]
    request: PathBuf,
}

#[derive(Serialize)]
struct BuildReport {
    output_path: PathBuf,
    bundle_sha256: DigestHex,
    manifest_sha256: DigestHex,
    release_signing_public_key: deployer_host::PublicKeyHex,
}

fn main() -> ExitCode {
    match run() {
        Ok(report) => match canonical_json(&report) {
            Ok(bytes) => {
                println!("{}", String::from_utf8_lossy(&bytes));
                ExitCode::SUCCESS
            }
            Err(error) => fail(&format!("serialize build report: {error}")),
        },
        Err(error) => fail(&error),
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<BuildReport, String> {
    let arguments = Arguments::parse();
    let request_metadata = fs::symlink_metadata(&arguments.request)
        .map_err(|error| format!("inspect build request: {error}"))?;
    if !request_metadata.file_type().is_file() {
        return Err("build request must be a regular non-symlink file".into());
    }
    let owner = request_metadata.uid();
    let request_bytes = read_stable_regular(
        &arguments.request,
        Some(owner),
        None,
        MAX_INSTALL_REQUEST_BYTES,
    )
    .map_err(|error| format!("read build request: {error}"))?;
    let request: BundleBuildRequest = parse_canonical_json(&request_bytes)
        .map_err(|error| format!("parse build request: {error}"))?;
    if request.schema_version != 1 {
        return Err("build request schema_version must be 1".into());
    }

    let compose_file = read_owned_asset(
        &request.compose_path,
        owner,
        MAX_RUNTIME_TEMPLATE_BYTES,
        "Compose template",
    )?;
    let caddyfile = read_owned_asset(
        &request.caddyfile_path,
        owner,
        MAX_RUNTIME_TEMPLATE_BYTES,
        "Caddyfile",
    )?;
    let message_server_initializer = read_owned_asset(
        &request.message_server_initializer_path,
        owner,
        MAX_RUNTIME_TEMPLATE_BYTES,
        "message-server initializer",
    )?;
    let agent_secret_materializer = read_owned_asset(
        &request.agent_secret_materializer_path,
        owner,
        MAX_RUNTIME_TEMPLATE_BYTES,
        "Agent secret materializer",
    )?;
    let message_server_entrypoint = read_owned_asset(
        &request.message_server_entrypoint_path,
        owner,
        MAX_RUNTIME_TEMPLATE_BYTES,
        "message-server entrypoint",
    )?;
    let capability_ca_initializer = read_owned_asset(
        &request.capability_ca_initializer_path,
        owner,
        MAX_RUNTIME_TEMPLATE_BYTES,
        "Capability CA initializer",
    )?;
    let postgres_entrypoint = read_owned_asset(
        &request.postgres_entrypoint_path,
        owner,
        MAX_RUNTIME_TEMPLATE_BYTES,
        "PostgreSQL entrypoint",
    )?;
    let postgres_initializer = read_owned_asset(
        &request.postgres_initializer_path,
        owner,
        MAX_RUNTIME_TEMPLATE_BYTES,
        "PostgreSQL initializer",
    )?;
    let updater_binary = read_owned_asset(
        &request.updater_binary_path,
        owner,
        MAX_UPDATER_ASSET_BYTES,
        "updater binary",
    )?;
    if DigestHex::calculate(&updater_binary) != request.updater_sha256 {
        return Err("updater binary does not match updater_sha256".into());
    }
    let updater_unit = read_owned_asset(
        &request.updater_unit_path,
        owner,
        MAX_RUNTIME_TEMPLATE_BYTES,
        "updater unit",
    )?;

    let seed_path = std::env::var_os(SIGNING_SEED_FILE_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{SIGNING_SEED_FILE_ENV} is required"))?;
    let output_identity = resolved_target(&request.output_bundle_path)?;
    let overwrites_input = [
        arguments.request.as_path(),
        request.compose_path.as_path(),
        request.caddyfile_path.as_path(),
        request.message_server_initializer_path.as_path(),
        request.agent_secret_materializer_path.as_path(),
        request.message_server_entrypoint_path.as_path(),
        request.capability_ca_initializer_path.as_path(),
        request.postgres_entrypoint_path.as_path(),
        request.postgres_initializer_path.as_path(),
        request.updater_binary_path.as_path(),
        request.updater_unit_path.as_path(),
        seed_path.as_path(),
    ]
    .iter()
    .map(fs::canonicalize)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| format!("resolve build input identity: {error}"))?
    .contains(&output_identity);
    if overwrites_input {
        return Err("output bundle path must not overwrite an input".into());
    }
    let seed_bytes = Zeroizing::new(
        read_stable_regular(&seed_path, Some(owner), Some(0o600), 32)
            .map_err(|error| format!("read signing seed: {error}"))?,
    );
    let seed_array: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signing seed must contain exactly 32 bytes")?;
    let seed = Zeroizing::new(seed_array);

    let built = build_bundle(
        &request.release,
        request.images,
        BundleAssets {
            compose_file,
            caddyfile,
            message_server_initializer,
            agent_secret_materializer,
            message_server_entrypoint,
            capability_ca_initializer,
            postgres_entrypoint,
            postgres_initializer,
            updater_binary,
            updater_unit,
            updater_version: request.updater_version,
            updater_source_revision: request.updater_source_revision,
            updater_source_url: request.updater_source_url,
        },
        &seed,
    )
    .map_err(|error| format!("build canonical bundle: {error}"))?;
    if built.bytes.len() > MAX_RELEASE_BUNDLE_BYTES {
        return Err("built bundle exceeded the fixed size limit".into());
    }
    write_atomic_public(&request.output_bundle_path, &built.bytes, owner)?;
    Ok(BuildReport {
        output_path: request.output_bundle_path,
        bundle_sha256: built.bundle_sha256,
        manifest_sha256: built.manifest_sha256,
        release_signing_public_key: built.release_signing_public_key,
    })
}

fn resolved_target(path: &Path) -> Result<PathBuf, String> {
    if path.exists() {
        return fs::canonicalize(path).map_err(|error| format!("resolve output path: {error}"));
    }
    let name = path
        .file_name()
        .ok_or_else(|| "output bundle path must name a file".to_owned())?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::canonicalize(parent)
        .map(|parent| parent.join(name))
        .map_err(|error| format!("resolve output directory: {error}"))
}

fn read_owned_asset(
    path: &Path,
    owner: u32,
    maximum_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    read_stable_regular(path, Some(owner), None, maximum_bytes)
        .map_err(|error| format!("read {label}: {error}"))
}

fn write_atomic_public(path: &Path, bytes: &[u8], owner: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect output directory: {error}"))?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.uid() != owner {
        return Err("output parent must be a real directory owned by the request owner".into());
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.file_type().is_file() || metadata.uid() != owner)
    {
        return Err("existing output must be a regular file owned by the request owner".into());
    }
    let temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("create temporary bundle: {error}"))?;
    let mut file = temporary.as_file();
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write bundle: {error}"))?;
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|error| format!("set bundle permissions: {error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("persist bundle: {error}"))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync output directory: {error}"))
}

fn fail(message: &str) -> ExitCode {
    eprintln!("bundle_builder_failed: {message}");
    ExitCode::FAILURE
}
