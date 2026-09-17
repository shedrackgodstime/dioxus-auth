use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::error::{AuthError, AuthResult};
use crate::transport::token::TokenStorage;

/// File-backed [`TokenStorage`] for native (desktop / mobile) clients.
///
/// On Unix, the file is created with mode `0600` (owner read/write only) so that
/// other processes running as the same user cannot read the raw session token.
/// If the file already exists with looser permissions, every write defensively
/// restores `0600` before the contents land.
///
/// On non-Unix platforms the mode bits are best-effort (the file is written
/// with default permissions) — the test suite gates on Unix.
pub struct FileTokenStorage {
    path: PathBuf,
}

impl FileTokenStorage {
    /// Create a new `FileTokenStorage` writing to the given path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Get the file path this storage reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl TokenStorage for FileTokenStorage {
    fn load(&self) -> Option<String> {
        match fs::read_to_string(&self.path) {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }
            Err(_) => None,
        }
    }

    fn save(&self, token: &str) -> AuthResult<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    AuthError::Store(format!(
                        "failed to create parent dir {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }

        write_secret(&self.path, token).map_err(|e| {
            AuthError::Store(format!(
                "failed to write token file {}: {e}",
                self.path.display()
            ))
        })
    }

    fn clear(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Persist `contents` atomically: write a sibling `.tmp` file, then rename it
/// over `path`. Rename is atomic within a filesystem, so a crash or power loss
/// mid-write can never leave a truncated token file behind.
#[cfg(unix)]
fn write_secret(path: &Path, contents: &str) -> io::Result<()> {
    use io::Write;
    let tmp = sibling_tmp_path(path);
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(contents.as_bytes())?;
    // Defensive: ensure the file mode is 0600 even if a `.tmp` file pre-existed
    // with looser permissions. The `mode(0o600)` above only applies at create time.
    let metadata = file.metadata()?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&tmp, perms)?;
    fs::rename(&tmp, path)
}

/// Non-Unix variant: no `0600` enforcement, but still atomic via rename.
#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &str) -> io::Result<()> {
    let tmp = sibling_tmp_path(path);
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path)
}

/// `secret.bin` -> `secret.bin.tmp` in the same directory (same filesystem, so rename is atomic).
fn sibling_tmp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_none_for_missing_file() {
        let dir = std::env::temp_dir().join(format!(
            "dioxus_auth_file_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("does_not_exist.token");

        let storage = FileTokenStorage::new(&path);
        assert_eq!(storage.load(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_is_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "dioxus_auth_file_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clear_idempotent.token");

        let storage = FileTokenStorage::new(&path);
        storage.save("token").unwrap();
        storage.clear();
        storage.clear(); // second clear must not panic

        let _ = std::fs::remove_dir_all(&dir);
    }
}
