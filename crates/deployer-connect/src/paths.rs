use std::path::{Path, PathBuf};

use crate::ConnectError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPlatform {
    WindowsAmd64,
    LinuxAmd64,
    MacAmd64,
    MacArm64,
}

impl LocalPlatform {
    /// Detects one of the four supported release targets.
    ///
    /// # Errors
    ///
    /// Returns an error for all other OS/architecture pairs.
    pub fn current() -> Result<Self, ConnectError> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("windows", "x86_64") => Ok(Self::WindowsAmd64),
            ("linux", "x86_64") => Ok(Self::LinuxAmd64),
            ("macos", "x86_64") => Ok(Self::MacAmd64),
            ("macos", "aarch64") => Ok(Self::MacArm64),
            (os, arch) => Err(ConnectError::UnsupportedPlatform(format!("{os}/{arch}"))),
        }
    }

    #[must_use]
    pub const fn release_target(self) -> &'static str {
        match self {
            Self::WindowsAmd64 => "windows-amd64",
            Self::LinuxAmd64 => "linux-amd64",
            Self::MacAmd64 => "darwin-amd64",
            Self::MacArm64 => "darwin-arm64",
        }
    }

    #[must_use]
    pub const fn archive_extension(self) -> &'static str {
        match self {
            Self::WindowsAmd64 => ".zip",
            Self::LinuxAmd64 | Self::MacAmd64 | Self::MacArm64 => ".tar.gz",
        }
    }

    const fn separator(self) -> char {
        match self {
            Self::WindowsAmd64 => '\\',
            Self::LinuxAmd64 | Self::MacAmd64 | Self::MacArm64 => '/',
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServicePaths {
    pub root: PathBuf,
    pub credentials: PathBuf,
    pub connect_dir: PathBuf,
    pub config: PathBuf,
    pub data_dir: PathBuf,
    pub matrix_session: PathBuf,
    pub binary: PathBuf,
    pub mcp_dir: PathBuf,
}

impl ServicePaths {
    /// Builds native paths below `~/.dirextalk/nodes/<service_id>`.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier could alias or escape its scope.
    pub fn new(home: &Path, service_id: &str) -> Result<Self, ConnectError> {
        validate_service_id(service_id)?;
        if !home.is_absolute() {
            return Err(ConnectError::InvalidServiceId(
                "home directory must be absolute".to_owned(),
            ));
        }
        let root = home.join(".dirextalk").join("nodes").join(service_id);
        let connect_dir = root.join("dirextalk-connect");
        let binary_name = if cfg!(windows) {
            "dirextalk-connect.exe"
        } else {
            "dirextalk-connect"
        };
        Ok(Self {
            credentials: root.join("credentials.json"),
            config: connect_dir.join("config.toml"),
            data_dir: connect_dir.join("data"),
            matrix_session: connect_dir.join("matrix-session.json"),
            binary: connect_dir.join(binary_name),
            mcp_dir: root.join("mcp"),
            connect_dir,
            root,
        })
    }

    /// Renders paths for one supported platform without host path conversion.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier could alias or escape its scope.
    pub fn render(
        platform: LocalPlatform,
        home: &str,
        service_id: &str,
    ) -> Result<RenderedServicePaths, ConnectError> {
        validate_service_id(service_id)?;
        let absolute_home = match platform {
            LocalPlatform::WindowsAmd64 => {
                let bytes = home.as_bytes();
                bytes.len() >= 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && matches!(bytes[2], b'/' | b'\\')
            }
            LocalPlatform::LinuxAmd64 | LocalPlatform::MacAmd64 | LocalPlatform::MacArm64 => {
                home.starts_with('/')
            }
        };
        if !absolute_home {
            return Err(ConnectError::InvalidServiceId(
                "home directory must be absolute for the target platform".to_owned(),
            ));
        }
        let separator = platform.separator();
        let join = |parts: &[&str]| {
            let mut value = home.trim_end_matches(['/', '\\']).to_owned();
            for part in parts {
                value.push(separator);
                value.push_str(part);
            }
            value
        };
        let root = join(&[".dirextalk", "nodes", service_id]);
        let connect_dir = format!("{root}{separator}dirextalk-connect");
        let binary_name = if platform == LocalPlatform::WindowsAmd64 {
            "dirextalk-connect.exe"
        } else {
            "dirextalk-connect"
        };
        Ok(RenderedServicePaths {
            credentials: format!("{root}{separator}credentials.json"),
            config: format!("{connect_dir}{separator}config.toml"),
            data_dir: format!("{connect_dir}{separator}data"),
            matrix_session: format!("{connect_dir}{separator}matrix-session.json"),
            binary: format!("{connect_dir}{separator}{binary_name}"),
            mcp_dir: format!("{root}{separator}mcp"),
            connect_dir,
            root,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedServicePaths {
    pub root: String,
    pub credentials: String,
    pub connect_dir: String,
    pub config: String,
    pub data_dir: String,
    pub matrix_session: String,
    pub binary: String,
    pub mcp_dir: String,
}

pub(crate) fn validate_service_id(service_id: &str) -> Result<(), ConnectError> {
    let valid = !service_id.is_empty()
        && service_id.len() <= 253
        && service_id != "."
        && service_id != ".."
        && service_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(ConnectError::InvalidServiceId(service_id.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_service_scoped_paths_for_all_supported_platforms() {
        let windows = ServicePaths::render(
            LocalPlatform::WindowsAmd64,
            r"C:\Users\Ada",
            "node.example.com",
        )
        .unwrap();
        assert_eq!(
            windows.config,
            r"C:\Users\Ada\.dirextalk\nodes\node.example.com\dirextalk-connect\config.toml"
        );
        assert!(windows.binary.ends_with("dirextalk-connect.exe"));
        assert_eq!(
            LocalPlatform::WindowsAmd64.release_target(),
            "windows-amd64"
        );
        assert_eq!(LocalPlatform::WindowsAmd64.archive_extension(), ".zip");

        for platform in [
            LocalPlatform::LinuxAmd64,
            LocalPlatform::MacAmd64,
            LocalPlatform::MacArm64,
        ] {
            let paths = ServicePaths::render(platform, "/Users/ada", "node.example.com").unwrap();
            assert_eq!(
                paths.config,
                "/Users/ada/.dirextalk/nodes/node.example.com/dirextalk-connect/config.toml"
            );
            assert!(
                !std::path::Path::new(&paths.binary)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
            );
        }
        assert_eq!(LocalPlatform::LinuxAmd64.release_target(), "linux-amd64");
        assert_eq!(LocalPlatform::MacAmd64.release_target(), "darwin-amd64");
        assert_eq!(LocalPlatform::MacArm64.release_target(), "darwin-arm64");
    }

    #[test]
    fn rejects_paths_disguised_as_service_ids() {
        for value in [
            "",
            "..",
            "../../escape",
            "MixedCase",
            "with/slash",
            "with\\slash",
        ] {
            assert!(ServicePaths::render(LocalPlatform::LinuxAmd64, "/home/a", value).is_err());
        }
        assert!(
            ServicePaths::render(LocalPlatform::LinuxAmd64, "relative", "valid.example").is_err()
        );
        assert!(
            ServicePaths::render(LocalPlatform::WindowsAmd64, "/unix", "valid.example").is_err()
        );
    }
}
