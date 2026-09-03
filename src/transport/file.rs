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
/// If the file already exists with looser permissions, the implementation does
/// not chmod it; the caller is responsible for fixing the permissions on
/// existing files.
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
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                eprintln!(
                    "[dioxus-auth] FileTokenStorage::load failed for {}: {e}",
                    self.path.display()
                );
                None
            }
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
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!(
                    "[dioxus-auth] FileTokenStorage::clear failed for {}: {e}",
                    self.path.display()
                );
            }
        }
    }
}

#[cfg(unix)]
fn write_secret(path: &Path, contents: &str) -> io::Result<()> {
    use io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    // Defensive: ensure the file mode is 0600 even if it pre-existed with looser
    // permissions. The `mode(0o600)` above only applies at create time.
    let metadata = file.metadata()?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &str) -> io::Result<()> {
    fs::write(path, contents)
}
