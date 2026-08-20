use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{GcpError, Result};

pub trait SecretStore: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<SecretString>>;
    fn set(&self, account: &str, value: &SecretString) -> Result<()>;
    fn delete(&self, account: &str) -> Result<()>;
}

pub trait PassphraseProvider: Send + Sync {
    fn passphrase(&self) -> Result<SecretString>;
}

#[derive(Clone)]
struct FixedPassphraseProvider {
    passphrase: SecretString,
}

impl PassphraseProvider for FixedPassphraseProvider {
    fn passphrase(&self) -> Result<SecretString> {
        Ok(self.passphrase.clone())
    }
}

#[derive(Debug, Clone)]
pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, account)
            .map_err(|error| GcpError::CredentialStorage(error.to_string()))
    }
}

impl SecretStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<SecretString>> {
        match self.entry(account)?.get_password() {
            Ok(value) => Ok(Some(SecretString::from(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(GcpError::CredentialStorage(error.to_string())),
        }
    }

    fn set(&self, account: &str, value: &SecretString) -> Result<()> {
        self.entry(account)?
            .set_password(value.expose_secret())
            .map_err(|error| GcpError::CredentialStorage(error.to_string()))
    }

    fn delete(&self, account: &str) -> Result<()> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(GcpError::CredentialStorage(error.to_string())),
        }
    }
}

#[derive(Clone)]
pub struct EncryptedFileStore {
    directory: PathBuf,
    service: String,
    passphrase_provider: Arc<dyn PassphraseProvider>,
}

impl std::fmt::Debug for EncryptedFileStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedFileStore")
            .field("directory", &self.directory)
            .field("service", &self.service)
            .field("passphrase_provider", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

impl EncryptedFileStore {
    #[must_use]
    pub fn new(
        directory: impl Into<PathBuf>,
        service: impl Into<String>,
        passphrase: SecretString,
    ) -> Self {
        Self::with_passphrase_provider(
            directory,
            service,
            Arc::new(FixedPassphraseProvider { passphrase }),
        )
    }

    #[must_use]
    pub fn with_passphrase_provider(
        directory: impl Into<PathBuf>,
        service: impl Into<String>,
        passphrase_provider: Arc<dyn PassphraseProvider>,
    ) -> Self {
        Self {
            directory: directory.into(),
            service: service.into(),
            passphrase_provider,
        }
    }

    fn path(&self, account: &str) -> PathBuf {
        let digest = Sha256::digest(format!("{}\0{account}", self.service).as_bytes());
        self.directory
            .join(format!("{}.credential", hex_lower(&digest)))
    }

    fn aad(&self, account: &str) -> Vec<u8> {
        format!("dirextalk-gcp-credential-v1\0{}\0{account}", self.service).into_bytes()
    }

    fn derive_key(&self, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let passphrase = self.passphrase_provider.passphrase()?;
        if passphrase.expose_secret().chars().count() < 16 {
            return Err(GcpError::CredentialStorage(
                "encrypted credential fallback requires a passphrase of at least 16 characters"
                    .into(),
            ));
        }
        let mut key = Zeroizing::new([0_u8; 32]);
        Argon2::default()
            .hash_password_into(passphrase.expose_secret().as_bytes(), salt, key.as_mut())
            .map_err(|_| GcpError::CredentialStorage("Argon2id key derivation failed".into()))?;
        Ok(key)
    }

    fn ensure_directory(&self) -> Result<()> {
        fs::create_dir_all(&self.directory)?;
        set_directory_permissions(&self.directory)?;
        Ok(())
    }

    fn atomic_write(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        self.ensure_directory()?;
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        set_file_permissions(path)?;
        Ok(())
    }
}

impl SecretStore for EncryptedFileStore {
    fn get(&self, account: &str) -> Result<Option<SecretString>> {
        let path = self.path(account);
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let envelope: Envelope = serde_json::from_slice(&bytes)
            .map_err(|_| GcpError::CredentialStorage("credential envelope is invalid".into()))?;
        if envelope.version != 1 {
            return Err(GcpError::CredentialStorage(
                "unsupported credential envelope version".into(),
            ));
        }
        let salt = decode_field("salt", &envelope.salt)?;
        let nonce = decode_field("nonce", &envelope.nonce)?;
        let ciphertext = decode_field("ciphertext", &envelope.ciphertext)?;
        if nonce.len() != 12 {
            return Err(GcpError::CredentialStorage(
                "credential nonce has invalid length".into(),
            ));
        }
        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| GcpError::CredentialStorage("invalid encryption key".into()))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &self.aad(account),
                },
            )
            .map_err(|_| GcpError::CredentialStorage("credential decryption failed".into()))?;
        let plaintext = Zeroizing::new(plaintext);
        let value = String::from_utf8(plaintext.to_vec())
            .map_err(|_| GcpError::CredentialStorage("credential is not valid UTF-8".into()))?;
        Ok(Some(SecretString::from(value)))
    }

    fn set(&self, account: &str, value: &SecretString) -> Result<()> {
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 12];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);
        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| GcpError::CredentialStorage("invalid encryption key".into()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: value.expose_secret().as_bytes(),
                    aad: &self.aad(account),
                },
            )
            .map_err(|_| GcpError::CredentialStorage("credential encryption failed".into()))?;
        let envelope = Envelope {
            version: 1,
            salt: URL_SAFE_NO_PAD.encode(salt),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        self.atomic_write(&self.path(account), &serde_json::to_vec(&envelope)?)
    }

    fn delete(&self, account: &str) -> Result<()> {
        match fs::remove_file(self.path(account)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// OS credentials are preferred. A configured Argon2id + AES-256-GCM file
/// store is used only when the platform keyring is unavailable.
pub struct CredentialStore {
    primary: Box<dyn SecretStore>,
    fallback: Box<dyn SecretStore>,
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialStore")
            .field("primary", &"OS keyring")
            .field("fallback", &"encrypted file")
            .finish()
    }
}

impl CredentialStore {
    #[must_use]
    pub fn new(primary: impl SecretStore + 'static, fallback: impl SecretStore + 'static) -> Self {
        Self {
            primary: Box::new(primary),
            fallback: Box::new(fallback),
        }
    }
}

impl SecretStore for CredentialStore {
    fn get(&self, account: &str) -> Result<Option<SecretString>> {
        match self.primary.get(account) {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) | Err(_) => self.fallback.get(account),
        }
    }

    fn set(&self, account: &str, value: &SecretString) -> Result<()> {
        match self.primary.set(account, value) {
            Ok(()) => {
                self.fallback.delete(account)?;
                Ok(())
            }
            Err(_) => self.fallback.set(account, value),
        }
    }

    fn delete(&self, account: &str) -> Result<()> {
        let primary = self.primary.delete(account);
        let fallback = self.fallback.delete(account);
        match (primary, fallback) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(()) | Err(_)) | (Ok(()), Err(error)) => Err(error),
        }
    }
}

fn decode_field(name: &str, value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| GcpError::CredentialStorage(format!("credential {name} is invalid")))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use secrecy::{ExposeSecret as _, SecretString};

    use super::{CredentialStore, EncryptedFileStore, PassphraseProvider, SecretStore};
    use crate::Result;

    struct CountingProvider {
        calls: Arc<AtomicUsize>,
        passphrase: &'static str,
    }

    impl PassphraseProvider for CountingProvider {
        fn passphrase(&self) -> Result<SecretString> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(SecretString::from(self.passphrase))
        }
    }

    enum PrimaryValue {
        Present(&'static str),
        Missing,
    }

    struct FakePrimaryStore(PrimaryValue);

    impl SecretStore for FakePrimaryStore {
        fn get(&self, _account: &str) -> Result<Option<SecretString>> {
            match self.0 {
                PrimaryValue::Present(value) => Ok(Some(SecretString::from(value))),
                PrimaryValue::Missing => Ok(None),
            }
        }

        fn set(&self, _account: &str, _value: &SecretString) -> Result<()> {
            Ok(())
        }

        fn delete(&self, _account: &str) -> Result<()> {
            Ok(())
        }
    }

    fn counting_provider(
        calls: &Arc<AtomicUsize>,
        passphrase: &'static str,
    ) -> Arc<dyn PassphraseProvider> {
        Arc::new(CountingProvider {
            calls: Arc::clone(calls),
            passphrase,
        })
    }

    #[test]
    fn primary_secret_does_not_request_fallback_passphrase() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        let store = CredentialStore::new(
            FakePrimaryStore(PrimaryValue::Present("keyring-secret")),
            fallback,
        );

        let loaded = store
            .get("operator@example.com")
            .expect("load")
            .expect("present");

        assert_eq!(loaded.expose_secret(), "keyring-secret");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn missing_primary_and_fallback_file_do_not_request_passphrase() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let fallback = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        let store = CredentialStore::new(FakePrimaryStore(PrimaryValue::Missing), fallback);

        assert!(store.get("operator@example.com").expect("load").is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fallback_requests_passphrase_only_when_encrypting_or_decrypting() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let store = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "correct horse battery staple"),
        );
        let secret = SecretString::from("refresh-token-super-secret");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        store.set("operator@example.com", &secret).expect("store");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let loaded = store
            .get("operator@example.com")
            .expect("load")
            .expect("present");

        assert_eq!(loaded.expose_secret(), secret.expose_secret());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn encrypted_file_round_trip_does_not_contain_secret() {
        let directory = tempfile::tempdir().expect("tempdir");
        let passphrase = "correct horse battery staple";
        let store = EncryptedFileStore::new(
            directory.path(),
            "dirextalk-test",
            SecretString::from(passphrase),
        );
        let secret = SecretString::from("refresh-token-super-secret");
        store.set("operator@example.com", &secret).expect("store");

        let raw = std::fs::read_to_string(
            std::fs::read_dir(directory.path())
                .expect("read dir")
                .next()
                .expect("entry")
                .expect("valid entry")
                .path(),
        )
        .expect("read envelope");
        assert!(!raw.contains(secret.expose_secret()));
        assert!(!raw.contains(passphrase));
        let loaded = store
            .get("operator@example.com")
            .expect("load")
            .expect("present");
        assert_eq!(loaded.expose_secret(), secret.expose_secret());
        let debug = format!("{store:?}");
        assert!(!debug.contains(secret.expose_secret()));
        assert!(!debug.contains(passphrase));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn encrypted_file_rejects_weak_provider_passphrase_when_used() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let store = EncryptedFileStore::with_passphrase_provider(
            directory.path(),
            "dirextalk-test",
            counting_provider(&calls, "too-short"),
        );
        assert!(
            store
                .set("operator@example.com", &SecretString::from("refresh-token"))
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
