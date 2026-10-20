//! The `fs.*` actions: `fs.list`, `fs.read`, `fs.write`, `fs.restore`,
//! `fs.delete`.
//!
//! Path rules are enforced before any I/O: the path must be absolute, free of
//! device names, verbatim prefixes and alternate data streams, and after
//! canonicalization (which resolves `..` and symlinks) it must sit inside one
//! of the configured roots. `fs.write` backs the old content up to
//! `data_dir/undo` (or marks a file it did not own as absent) before writing,
//! so `fs.restore` can undo the write with the same arguments.

use crate::actions::HostEffects;
use fewshot_gate::EffectError;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// File names that name a console device or port, not a file.
const DEVICES: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2",
    "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// The most `fs.read` will return.
const MAX_READ: u64 = 1024 * 1024;
/// The most `fs.list` will name.
const MAX_ENTRIES: usize = 10_000;

/// Takes argument `index`; the gate already checked the arity.
fn arg<'a>(args: &'a [&'a [u8]], index: usize) -> &'a [u8] {
    args.get(index).copied().expect("arity is checked by the gate")
}

/// Takes argument `index` as UTF-8 text.
fn arg_utf8<'a>(args: &'a [&'a [u8]], index: usize, what: &str) -> Result<&'a str, EffectError> {
    std::str::from_utf8(arg(args, index)).map_err(|_| EffectError(format!("{what} must be valid UTF-8")))
}

/// Whether `name` is a reserved device name, case-insensitive, extension
/// removed (`CON`, `nul.txt`, `Com1.tmp`).
fn is_device(name: &str) -> bool {
    let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
    DEVICES.contains(&stem.to_ascii_lowercase().as_str())
}

/// The path rules, enforced before any I/O.
fn resolve(roots: &[PathBuf], raw: &str, must_exist: bool) -> Result<PathBuf, EffectError> {
    if raw.is_empty() {
        return Err(EffectError("path must not be empty".into()));
    }
    if raw.contains('\0') {
        return Err(EffectError("path must not contain a NUL byte".into()));
    }
    if raw.starts_with("\\\\?\\") || raw.starts_with("\\\\.\\") || raw.starts_with("//?/") || raw.starts_with("//./") {
        return Err(EffectError("path must not use a verbatim or device prefix".into()));
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(EffectError("path must be absolute".into()));
    }

    for component in path.components() {
        let Some(name) = component.as_os_str().to_str() else {
            return Err(EffectError("path must be valid UTF-8".into()));
        };
        if is_device(name) {
            return Err(EffectError(format!("'{name}' names a device, not a file")));
        }
        // The drive prefix is the only component that may carry ':'.
        #[cfg(windows)]
        if !matches!(component, std::path::Component::Prefix(_)) && name.contains(':') {
            return Err(EffectError("path must not name an alternate data stream".into()));
        }
    }

    let path = if must_exist {
        std::fs::canonicalize(path).map_err(|_| EffectError("path does not exist".into()))?
    } else {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Err(EffectError("path must end in a file name, not a separator".into()));
        };
        if name == "." || name == ".." {
            return Err(EffectError("path must not end in '.' or '..'".into()));
        }
        let parent =
            path.parent().ok_or_else(|| EffectError("path must end in a file name, not a separator".into()))?;
        let joined = std::fs::canonicalize(parent)
            .map_err(|_| EffectError(format!("{} does not exist", parent.display())))?
            .join(name);
        // If the name already exists it may be a symlink out of the root:
        // resolve it fully, so the check below sees where a write would land.
        if joined.symlink_metadata().is_ok() {
            std::fs::canonicalize(&joined).map_err(|_| EffectError("path is a broken link".into()))?
        } else {
            joined
        }
    };

    if !roots.iter().any(|root| path.starts_with(root)) {
        return Err(EffectError("path is outside every configured root".into()));
    }
    Ok(path)
}

/// The undo key: SHA-256 of (canonical path, one NUL byte, content).
fn undo_key(path: &Path, content: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(path.as_os_str().to_string_lossy().as_bytes());
    hasher.update([0]);
    hasher.update(content);
    hasher.finalize().into()
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("a String never fails to write into");
    }
    s
}

/// `fs.list dir`: the entries of `dir`, one per line, directories suffixed
/// with `/`, sorted by name.
pub(crate) fn list(host: &HostEffects, args: &[&[u8]]) -> Result<Vec<u8>, EffectError> {
    let dir = resolve(host.roots(), arg_utf8(args, 0, "dir")?, true)?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| EffectError(format!("cannot list directory: {e}")))? {
        let entry = entry.map_err(|e| EffectError(format!("cannot list directory: {e}")))?;
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        let name = entry.file_name().to_string_lossy().into_owned();
        names.push(if is_dir { format!("{name}/") } else { name });
        if names.len() > MAX_ENTRIES {
            return Err(EffectError(format!("directory has more than {MAX_ENTRIES} entries")));
        }
    }
    names.sort();
    Ok(names.join("\n").into_bytes())
}

/// `fs.read path`: the file's bytes, at most 1 MiB.
pub(crate) fn read(host: &HostEffects, args: &[&[u8]]) -> Result<Vec<u8>, EffectError> {
    let path = resolve(host.roots(), arg_utf8(args, 0, "path")?, true)?;
    let meta = std::fs::metadata(&path).map_err(|e| EffectError(format!("cannot read file: {e}")))?;
    if !meta.is_file() {
        return Err(EffectError(format!("{} is not a regular file", path.display())));
    }
    if meta.len() > MAX_READ {
        return Err(EffectError("file is larger than 1 MiB".into()));
    }
    let file = std::fs::File::open(&path).map_err(|e| EffectError(format!("cannot read file: {e}")))?;
    let mut bytes = Vec::new();
    // Take one extra byte so a file that grows between the checks still fails.
    file.take(MAX_READ + 1).read_to_end(&mut bytes).map_err(|e| EffectError(format!("cannot read file: {e}")))?;
    if (bytes.len() as u64) > MAX_READ {
        return Err(EffectError("file is larger than 1 MiB".into()));
    }
    Ok(bytes)
}

/// `fs.write path content`: backs up the old content (or an absence marker)
/// and writes `content`, creating the file if needed.
pub(crate) fn write(host: &HostEffects, args: &[&[u8]]) -> Result<Vec<u8>, EffectError> {
    let path = resolve(host.roots(), arg_utf8(args, 0, "path")?, false)?;
    let content = arg(args, 1);
    let undo = host.data_dir().join("undo");
    let key = hex(&undo_key(&path, content));
    if path.exists() {
        std::fs::copy(&path, undo.join(&key)).map_err(|e| EffectError(format!("cannot back up old content: {e}")))?;
    } else {
        std::fs::File::create(undo.join(format!("{key}.absent")))
            .map_err(|e| EffectError(format!("cannot record that the file was absent: {e}")))?;
    }
    std::fs::write(&path, content).map_err(|e| EffectError(format!("cannot write file: {e}")))?;
    Ok(Vec::new())
}

/// `fs.restore path content`: the compensation of `fs.write`, called by the
/// gate with the same arguments. Restores the backed-up content, or removes
/// a file the write created.
pub(crate) fn restore(host: &HostEffects, args: &[&[u8]]) -> Result<Vec<u8>, EffectError> {
    let raw = arg_utf8(args, 0, "path")?;
    let content = arg(args, 1);
    // The file exists if the write took effect; resolve either way.
    let path =
        if Path::new(raw).exists() { resolve(host.roots(), raw, true)? } else { resolve(host.roots(), raw, false)? };
    let undo = host.data_dir().join("undo");
    let key = hex(&undo_key(&path, content));
    let backup = undo.join(&key);
    let absent = undo.join(format!("{key}.absent"));
    if backup.exists() {
        std::fs::copy(&backup, &path).map_err(|e| EffectError(format!("cannot restore: {e}")))?;
        std::fs::remove_file(&backup).map_err(|e| EffectError(format!("cannot remove the undo copy: {e}")))?;
    } else if absent.exists() {
        match std::fs::remove_file(&path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(EffectError(format!("cannot remove the created file: {e}"))),
        }
        std::fs::remove_file(&absent).map_err(|e| EffectError(format!("cannot remove the absent marker: {e}")))?;
    } else {
        return Err(EffectError("nothing to restore".into()));
    }
    Ok(Vec::new())
}

/// `fs.delete path`: moves the file to `data_dir/trash`, never unlinks
/// directly.
pub(crate) fn delete(host: &HostEffects, args: &[&[u8]]) -> Result<Vec<u8>, EffectError> {
    let path = resolve(host.roots(), arg_utf8(args, 0, "path")?, true)?;
    let meta = std::fs::metadata(&path).map_err(|e| EffectError(format!("cannot move to trash: {e}")))?;
    if !meta.is_file() {
        return Err(EffectError(format!("{} is not a regular file", path.display())));
    }
    let name = path.file_name().expect("a resolved path ends in a file name");
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis());
    let trash = host.data_dir().join("trash");
    let mut dest = trash.join(format!("{stamp}-{}", name.to_string_lossy()));
    let mut bump = 2;
    while dest.exists() {
        dest = trash.join(format!("{stamp}-{}-{bump}", name.to_string_lossy()));
        bump += 1;
    }
    if std::fs::rename(&path, &dest).is_err() {
        // rename fails across volumes; copy, then remove.
        std::fs::copy(&path, &dest).map_err(|e| EffectError(format!("cannot move to trash: {e}")))?;
        std::fs::remove_file(&path).map_err(|e| EffectError(format!("cannot move to trash: {e}")))?;
    }
    Ok(Vec::new())
}
