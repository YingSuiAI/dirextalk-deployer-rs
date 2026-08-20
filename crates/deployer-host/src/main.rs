#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("dirextalk-host-installer is supported only on Linux");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use deployer_host::{
        BUNDLE_PATH, DigestHex, InstallOutcome, Installer, LinuxBackend, MAX_INSTALL_REQUEST_BYTES,
        MAX_RECEIPT_KEY_BYTES, MAX_RELEASE_BUNDLE_BYTES, RECEIPT_KEY_PATH, REQUEST_PATH,
        canonical_json,
    };
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use zeroize::Zeroizing;

    const HOST_INSTALLER_PATH: &str = "/var/tmp/dirextalk-host-installer";
    const MAX_HOST_INSTALLER_BYTES: usize = 64 * 1024 * 1024;

    #[derive(Debug, Parser)]
    #[command(name = "dirextalk-host-installer", disable_help_subcommand = true)]
    struct Arguments {
        #[arg(long, value_parser = parse_digest)]
        request_sha256: DigestHex,
    }

    fn parse_digest(value: &str) -> Result<DigestHex, String> {
        DigestHex::parse(value).map_err(|error| error.to_string())
    }

    pub fn run() -> ExitCode {
        let arguments = Arguments::parse();
        let outcome = match load_inputs() {
            Ok(inputs) => {
                let outcome = Installer::new(LinuxBackend).install(
                    &arguments.request_sha256,
                    &inputs.request,
                    &inputs.bundle,
                    &inputs.key,
                );
                if matches!(outcome, InstallOutcome::Success(_))
                    && let Err(message) = cleanup_staged_inputs(&inputs)
                {
                    eprintln!(
                        "infrastructure_failure: cleanup verified staging artifacts: {message}"
                    );
                    return ExitCode::from(1);
                }
                outcome
            }
            Err(message) => InstallOutcome::Failure {
                error: deployer_host::InstallFailure {
                    kind: deployer_host::FailureKind::Infrastructure,
                    message,
                },
            },
        };
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
        installer_identity: FileIdentity,
        request_identity: FileIdentity,
        bundle_identity: FileIdentity,
        key_identity: FileIdentity,
    }

    fn load_inputs() -> Result<StagedInputs, String> {
        let (_installer, installer_identity) = read_identified_regular(
            Path::new(HOST_INSTALLER_PATH),
            0o700,
            MAX_HOST_INSTALLER_BYTES,
        )?;
        let executable = fs::metadata("/proc/self/exe")
            .map_err(|error| format!("inspect running host installer: {error}"))?;
        if !installer_identity.matches_metadata(&executable) {
            return Err("staged host installer is not the running executable".into());
        }
        let (request, request_identity) =
            read_identified_regular(Path::new(REQUEST_PATH), 0o600, MAX_INSTALL_REQUEST_BYTES)?;
        let (bundle, bundle_identity) =
            read_identified_regular(Path::new(BUNDLE_PATH), 0o600, MAX_RELEASE_BUNDLE_BYTES)?;
        let (key, key_identity) =
            read_identified_regular(Path::new(RECEIPT_KEY_PATH), 0o600, MAX_RECEIPT_KEY_BYTES)?;
        Ok(StagedInputs {
            request,
            bundle,
            key: Zeroizing::new(key),
            installer_identity,
            request_identity,
            bundle_identity,
            key_identity,
        })
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        uid: u32,
        gid: u32,
        mode: u32,
        size: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        sha256: DigestHex,
    }

    impl FileIdentity {
        fn from_metadata(metadata: &fs::Metadata, sha256: DigestHex) -> Self {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode(),
                size: metadata.len(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                sha256,
            }
        }

        fn matches_metadata(&self, metadata: &fs::Metadata) -> bool {
            self.device == metadata.dev()
                && self.inode == metadata.ino()
                && self.uid == metadata.uid()
                && self.gid == metadata.gid()
                && self.mode == metadata.mode()
                && self.size == metadata.len()
                && self.modified_seconds == metadata.mtime()
                && self.modified_nanoseconds == metadata.mtime_nsec()
        }
    }

    fn read_identified_regular(
        path: &Path,
        expected_mode: u32,
        maximum_bytes: usize,
    ) -> Result<(Vec<u8>, FileIdentity), String> {
        let before = fs::symlink_metadata(path)
            .map_err(|error| format!("inspect staged {}: {error}", path.display()))?;
        if !before.file_type().is_file()
            || before.mode() & 0o777 != expected_mode
            || before.len() > u64::try_from(maximum_bytes).unwrap_or(u64::MAX)
        {
            return Err(format!(
                "staged file identity, mode, or size is invalid: {}",
                path.display()
            ));
        }
        let mut file = fs::File::open(path)
            .map_err(|error| format!("open staged {}: {error}", path.display()))?;
        let opened = file
            .metadata()
            .map_err(|error| format!("inspect open staged {}: {error}", path.display()))?;
        let before_identity = FileIdentity::from_metadata(&before, DigestHex::calculate(b""));
        if !before_identity.matches_metadata(&opened) {
            return Err(format!(
                "staged file changed while opening: {}",
                path.display()
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(maximum_bytes));
        Read::by_ref(&mut file)
            .take(u64::try_from(maximum_bytes).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read staged {}: {error}", path.display()))?;
        if bytes.len() > maximum_bytes {
            return Err(format!(
                "staged file exceeds its fixed limit: {}",
                path.display()
            ));
        }
        let after = file
            .metadata()
            .map_err(|error| format!("reinspect open staged {}: {error}", path.display()))?;
        let path_now = fs::symlink_metadata(path)
            .map_err(|error| format!("reinspect staged path {}: {error}", path.display()))?;
        if !before_identity.matches_metadata(&after) || !before_identity.matches_metadata(&path_now)
        {
            return Err(format!(
                "staged file identity changed while reading: {}",
                path.display()
            ));
        }
        let sha256 = DigestHex::calculate(&bytes);
        Ok((bytes, FileIdentity::from_metadata(&after, sha256)))
    }

    struct CleanupArtifact<'a> {
        path: PathBuf,
        identity: &'a FileIdentity,
        expected_mode: u32,
        maximum_bytes: usize,
    }

    fn cleanup_staged_inputs(inputs: &StagedInputs) -> Result<(), String> {
        cleanup_exact_artifacts(&[
            CleanupArtifact {
                path: PathBuf::from(HOST_INSTALLER_PATH),
                identity: &inputs.installer_identity,
                expected_mode: 0o700,
                maximum_bytes: MAX_HOST_INSTALLER_BYTES,
            },
            CleanupArtifact {
                path: PathBuf::from(REQUEST_PATH),
                identity: &inputs.request_identity,
                expected_mode: 0o600,
                maximum_bytes: MAX_INSTALL_REQUEST_BYTES,
            },
            CleanupArtifact {
                path: PathBuf::from(BUNDLE_PATH),
                identity: &inputs.bundle_identity,
                expected_mode: 0o600,
                maximum_bytes: MAX_RELEASE_BUNDLE_BYTES,
            },
            CleanupArtifact {
                path: PathBuf::from(RECEIPT_KEY_PATH),
                identity: &inputs.key_identity,
                expected_mode: 0o600,
                maximum_bytes: MAX_RECEIPT_KEY_BYTES,
            },
        ])
    }

    fn cleanup_exact_artifacts(artifacts: &[CleanupArtifact<'_>]) -> Result<(), String> {
        for artifact in artifacts {
            let (_, current) = read_identified_regular(
                &artifact.path,
                artifact.expected_mode,
                artifact.maximum_bytes,
            )?;
            if current != *artifact.identity {
                return Err(format!(
                    "staging artifact was substituted before cleanup: {}",
                    artifact.path.display()
                ));
            }
            let immediately_before = fs::symlink_metadata(&artifact.path).map_err(|error| {
                format!(
                    "revalidate staging artifact before cleanup {}: {error}",
                    artifact.path.display()
                )
            })?;
            if !artifact.identity.matches_metadata(&immediately_before) {
                return Err(format!(
                    "staging artifact identity changed before removal: {}",
                    artifact.path.display()
                ));
            }
            fs::remove_file(&artifact.path)
                .map_err(|error| format!("remove staged {}: {error}", artifact.path.display()))?;
            match fs::symlink_metadata(&artifact.path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(format!(
                        "staging artifact remains after cleanup: {}",
                        artifact.path.display()
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "verify staging cleanup {}: {error}",
                        artifact.path.display()
                    ));
                }
            }
        }
        Ok(())
    }

    fn print_json<T: serde::Serialize>(value: &T) {
        match canonical_json(value) {
            Ok(bytes) => println!("{}", String::from_utf8_lossy(&bytes)),
            Err(error) => eprintln!("receipt serialization failed: {error}"),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn staged(path: &Path, bytes: &[u8], mode: u32) -> FileIdentity {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            read_identified_regular(path, mode, 1024).unwrap().1
        }

        #[test]
        fn successful_cleanup_leaves_no_staging_key_readable() {
            let directory = tempfile::tempdir().unwrap();
            let receipt = directory.path().join("installed-receipt.json");
            fs::write(&receipt, b"signed receipt").unwrap();
            let paths = ["installer", "request", "bundle", "receipt-key"]
                .map(|name| directory.path().join(name));
            let identities = [
                staged(&paths[0], b"installer", 0o700),
                staged(&paths[1], b"request", 0o600),
                staged(&paths[2], b"bundle", 0o600),
                staged(&paths[3], b"secret-key", 0o600),
            ];
            let artifacts = paths
                .iter()
                .zip(identities.iter())
                .enumerate()
                .map(|(index, (path, identity))| CleanupArtifact {
                    path: path.clone(),
                    identity,
                    expected_mode: if index == 0 { 0o700 } else { 0o600 },
                    maximum_bytes: 1024,
                })
                .collect::<Vec<_>>();
            cleanup_exact_artifacts(&artifacts).unwrap();
            assert!(paths.iter().all(|path| !path.exists()));
            assert_eq!(
                fs::read(&paths[3]).unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
            assert_eq!(fs::read(receipt).unwrap(), b"signed receipt");
        }

        #[test]
        fn interrupted_cleanup_retains_key_and_installed_receipt() {
            let directory = tempfile::tempdir().unwrap();
            let receipt = directory.path().join("installed-receipt.json");
            fs::write(&receipt, b"signed receipt").unwrap();
            let paths = ["installer", "request", "bundle", "receipt-key"]
                .map(|name| directory.path().join(name));
            let identities = [
                staged(&paths[0], b"installer", 0o700),
                staged(&paths[1], b"request", 0o600),
                staged(&paths[2], b"bundle", 0o600),
                staged(&paths[3], b"secret-key", 0o600),
            ];
            fs::write(&paths[1], b"interrupted replacement").unwrap();
            let artifacts = paths
                .iter()
                .zip(identities.iter())
                .enumerate()
                .map(|(index, (path, identity))| CleanupArtifact {
                    path: path.clone(),
                    identity,
                    expected_mode: if index == 0 { 0o700 } else { 0o600 },
                    maximum_bytes: 1024,
                })
                .collect::<Vec<_>>();
            assert!(cleanup_exact_artifacts(&artifacts).is_err());
            assert!(!paths[0].exists());
            assert!(paths[1].exists() && paths[2].exists() && paths[3].exists());
            assert_eq!(fs::read(&paths[3]).unwrap(), b"secret-key");
            assert_eq!(fs::read(receipt).unwrap(), b"signed receipt");
        }

        #[test]
        fn same_content_inode_substitution_fails_closed() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("receipt-key");
            let replacement = directory.path().join("replacement");
            let identity = staged(&path, b"secret-key", 0o600);
            staged(&replacement, b"secret-key", 0o600);
            fs::rename(&replacement, &path).unwrap();
            let artifacts = [CleanupArtifact {
                path: path.clone(),
                identity: &identity,
                expected_mode: 0o600,
                maximum_bytes: 1024,
            }];
            assert!(cleanup_exact_artifacts(&artifacts).is_err());
            assert_eq!(fs::read(path).unwrap(), b"secret-key");
        }
    }
}
