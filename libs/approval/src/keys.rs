//! The approval signing key: created and held by the approval app only.
//! The runtime reads just the public half ([`load_public`]).

use crate::wire::{hex, unhex};
use fewshot_gate::{Approver, VerifyingKey};
use std::fmt;
use std::path::{Path, PathBuf};

/// Why a key could not be loaded or created.
#[derive(Debug)]
pub enum KeyError {
    /// A key file could not be read or written.
    Io(String),
    /// A key file is not the expected hex.
    Malformed(PathBuf),
    /// The system random source failed.
    Random(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Io(m) => write!(f, "approval key: {m}"),
            KeyError::Malformed(p) => write!(f, "approval key: {} is not a valid key file", p.display()),
            KeyError::Random(m) => write!(f, "approval key: no randomness: {m}"),
        }
    }
}

impl std::error::Error for KeyError {}

const SECRET: &str = "approval.key";
const PUBLIC: &str = "approval.pub";

fn io(e: std::io::Error) -> KeyError {
    KeyError::Io(e.to_string())
}

/// Loads the signing key from `dir`, creating it (and `approval.pub`) on first use.
pub fn load_or_create(dir: &Path) -> Result<Approver, KeyError> {
    let secret_path = dir.join(SECRET);
    if secret_path.exists() {
        let text = std::fs::read_to_string(&secret_path).map_err(io)?;
        let secret = unhex::<32>(text.trim()).map_err(|_| KeyError::Malformed(secret_path))?;
        return Ok(Approver::from_secret(secret));
    }
    std::fs::create_dir_all(dir).map_err(io)?;
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| KeyError::Random(e.to_string()))?;
    write_secret(&secret_path, &hex(&secret))?;
    let approver = Approver::from_secret(secret);
    std::fs::write(dir.join(PUBLIC), hex(&approver.verifying_key().to_bytes())).map_err(io)?;
    Ok(approver)
}

#[cfg(unix)]
fn write_secret(path: &Path, text: &str) -> Result<(), KeyError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(io)?;
    f.write_all(text.as_bytes()).map_err(io)
}

/// On Windows the file inherits the per-user profile ACL (docs/LIMITATIONS.md).
#[cfg(not(unix))]
fn write_secret(path: &Path, text: &str) -> Result<(), KeyError> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(io)?;
    f.write_all(text.as_bytes()).map_err(io)
}

/// Loads the public key the gate verifies approvals against.
pub fn load_public(dir: &Path) -> Result<VerifyingKey, KeyError> {
    let path = dir.join(PUBLIC);
    let text = std::fs::read_to_string(&path).map_err(io)?;
    let bytes = unhex::<32>(text.trim()).map_err(|_| KeyError::Malformed(path.clone()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::Malformed(path))
}

/// Where the key lives: `$FEWSHOT_CONFIG_DIR`, else the user's config
/// directory plus `fewshot`.
pub fn default_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("FEWSHOT_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.unwrap_or_else(|| PathBuf::from(".")).join("fewshot")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_created_once_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_create(dir.path()).unwrap().verifying_key();
        let b = load_or_create(dir.path()).unwrap().verifying_key();
        assert_eq!(a, b);
        assert_eq!(load_public(dir.path()).unwrap(), a);
    }

    #[test]
    fn a_corrupted_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SECRET), "not hex").unwrap();
        assert!(matches!(load_or_create(dir.path()), Err(KeyError::Malformed(_))));
    }

    #[cfg(unix)]
    #[test]
    fn the_secret_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        load_or_create(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join(SECRET)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
