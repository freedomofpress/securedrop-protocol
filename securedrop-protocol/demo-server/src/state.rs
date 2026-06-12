use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;

pub fn data_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("press", "freedom", "securedrop-demo-server")
        .context("locating a home directory for the data dir")?;
    Ok(dirs.data_dir().to_path_buf())
}

pub fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents)?;
    Ok(())
}
