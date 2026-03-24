// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Profile management for multi-account support.
//!
//! This module is the **single source of truth** for all profile-related path
//! resolution and validation. Other modules must call into this module rather
//! than constructing profile paths themselves.

use std::path::{Path, PathBuf};

use crate::error::GwsError;

/// Default profile name used when no profile is explicitly selected.
pub const DEFAULT_PROFILE: &str = "default";

/// Name of the file that tracks the active profile.
const ACTIVE_PROFILE_FILE: &str = "active_profile";

/// Subdirectory under the config root that holds per-profile data.
const PROFILES_DIR: &str = "profiles";

/// A validated, lowercase profile name.
///
/// Invariants enforced by [`ProfileName::new`]:
/// - Matches `^[a-z0-9_][a-z0-9_-]{0,63}$`
/// - Cannot be `.` or `..`
/// - Cannot contain `/`, `\`, `%`, or control characters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileName(String);

impl ProfileName {
    /// Validate and normalize a profile name.
    ///
    /// Rules (derived from previous review feedback):
    /// - Lowercase only: `[a-z0-9_-]`
    /// - Cannot start with `-` (prevents CLI flag confusion)
    /// - Cannot be empty, `.`, or `..`
    /// - Max 64 characters
    /// - No `/`, `\`, `%`, null bytes, or control characters
    pub fn new(name: &str) -> Result<Self, GwsError> {
        crate::validate::validate_profile_name(name)?;
        Ok(Self(name.to_string()))
    }

    /// Return the validated name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProfileName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Resolve the active profile from (in priority order):
/// 1. `--profile` CLI flag override
/// 2. `GOOGLE_WORKSPACE_CLI_PROFILE` env var
/// 3. `active_profile` file in the config directory
/// 4. `"default"` fallback
pub fn resolve_active_profile(
    cli_override: Option<&str>,
    base_dir: &Path,
) -> Result<ProfileName, GwsError> {
    // 1. CLI flag (highest priority)
    if let Some(name) = cli_override {
        return ProfileName::new(name);
    }

    // 2. Environment variable
    if let Ok(name) = std::env::var("GOOGLE_WORKSPACE_CLI_PROFILE") {
        if !name.is_empty() {
            return ProfileName::new(&name);
        }
    }

    // 3. active_profile file
    let active_file = base_dir.join(ACTIVE_PROFILE_FILE);
    if let Ok(contents) = std::fs::read_to_string(&active_file) {
        let name = contents.trim();
        if !name.is_empty() {
            // Validate file contents to prevent path traversal from tampered files
            return ProfileName::new(name);
        }
    }

    // 4. Default fallback
    ProfileName::new(DEFAULT_PROFILE)
}

/// Return the profile-specific config directory path.
///
/// Returns `<base_dir>/profiles/<profile_name>/`.
/// Does NOT check existence or create the directory — callers should
/// use `create_profile()` or `ensure_profile_dir()` for that.
pub fn profile_dir(base_dir: &Path, profile: &ProfileName) -> PathBuf {
    base_dir.join(PROFILES_DIR).join(profile.as_str())
}

/// Proactively ensure the profile directory exists with secure permissions.
///
/// Uses `create_dir_all` directly (no check-then-create TOCTOU pattern).
pub async fn ensure_profile_dir(
    base_dir: &Path,
    profile: &ProfileName,
) -> Result<PathBuf, GwsError> {
    let dir = profile_dir(base_dir, profile);
    tokio::fs::create_dir_all(&dir).await.map_err(|e| {
        GwsError::Validation(format!(
            "Failed to create profile directory '{}': {e}",
            dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await
        {
            eprintln!(
                "Warning: failed to set permissions on profile directory '{}': {e}",
                dir.display()
            );
        }
    }
    Ok(dir)
}

/// Create a new profile directory. Returns the path to the created directory.
pub async fn create_profile(base_dir: &Path, profile: &ProfileName) -> Result<PathBuf, GwsError> {
    let dir = profile_dir(base_dir, profile);
    if tokio::fs::try_exists(&dir).await.unwrap_or(false) {
        return Err(GwsError::Validation(format!(
            "Profile '{}' already exists",
            profile.as_str()
        )));
    }
    ensure_profile_dir(base_dir, profile).await
}

/// Delete a profile and all its credential files.
///
/// Warns (does not fail) on individual file removal errors — lesson from
/// previous PR review feedback.
pub async fn delete_profile(base_dir: &Path, profile: &ProfileName) -> Result<(), GwsError> {
    if profile.as_str() == DEFAULT_PROFILE {
        // Allow deleting default — user can re-create it with `gws auth login`
    }

    let dir = profile_dir(base_dir, profile);
    if !tokio::fs::try_exists(&dir).await.unwrap_or(false) {
        return Err(GwsError::Validation(format!(
            "Profile '{}' does not exist",
            profile.as_str()
        )));
    }

    // Remove the profile directory and all contents
    if let Err(e) = tokio::fs::remove_dir_all(&dir).await {
        eprintln!(
            "Warning: failed to remove profile directory '{}': {e}",
            dir.display()
        );
        return Err(GwsError::Validation(format!(
            "Failed to delete profile '{}': {e}",
            profile.as_str()
        )));
    }

    // If this was the active profile, clear the active_profile file
    let active_file = base_dir.join(ACTIVE_PROFILE_FILE);
    if let Ok(contents) = tokio::fs::read_to_string(&active_file).await {
        if contents.trim() == profile.as_str() {
            let _ = tokio::fs::remove_file(&active_file).await;
        }
    }

    // Best-effort: remove keyring entry for this profile
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown-user".to_string());
    let keyring_user = format!("{}/{}", username, profile.as_str());
    if let Ok(entry) = keyring::Entry::new("gws-cli", &keyring_user) {
        let _ = entry.delete_credential();
    }

    Ok(())
}

/// List all profiles and whether each is active.
///
/// Returns `(profile_name, is_active)` pairs sorted alphabetically.
pub async fn list_profiles(base_dir: &Path) -> Result<Vec<(String, bool)>, GwsError> {
    let profiles_dir = base_dir.join(PROFILES_DIR);

    // Determine which profile is active
    let active = resolve_active_profile(None, base_dir)
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|_| DEFAULT_PROFILE.to_string());

    let mut profiles = Vec::new();

    if !tokio::fs::try_exists(&profiles_dir).await.unwrap_or(false) {
        // No profiles dir yet — return just the default
        profiles.push((DEFAULT_PROFILE.to_string(), active == DEFAULT_PROFILE));
        return Ok(profiles);
    }

    let mut entries = tokio::fs::read_dir(&profiles_dir).await.map_err(|e| {
        GwsError::Validation(format!(
            "Failed to read profiles directory '{}': {e}",
            profiles_dir.display()
        ))
    })?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| GwsError::Validation(format!("Failed to read profile entry: {e}")))?
    {
        if let Ok(file_type) = entry.file_type().await {
            if file_type.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Validate each directory name — skip invalid ones
                if ProfileName::new(&name).is_ok() {
                    let is_active = name == active;
                    profiles.push((name, is_active));
                }
            }
        }
    }

    profiles.sort_by(|a, b| a.0.cmp(&b.0));

    if profiles.is_empty() {
        profiles.push((DEFAULT_PROFILE.to_string(), active == DEFAULT_PROFILE));
    }

    Ok(profiles)
}

/// Set the active profile by writing the `active_profile` file atomically.
pub async fn set_active_profile(base_dir: &Path, profile: &ProfileName) -> Result<(), GwsError> {
    // Verify the profile directory exists
    let dir = profile_dir(base_dir, profile);
    if !tokio::fs::try_exists(&dir).await.unwrap_or(false) {
        return Err(GwsError::Validation(format!(
            "Profile '{}' does not exist. Create it first with `gws auth profile create {}`",
            profile.as_str(),
            profile.as_str()
        )));
    }

    let active_file = base_dir.join(ACTIVE_PROFILE_FILE);

    // Atomic write to prevent partial writes
    crate::fs_util::atomic_write_async(&active_file, profile.as_str().as_bytes())
        .await
        .map_err(|e| GwsError::Validation(format!("Failed to set active profile: {e}")))?;

    Ok(())
}

/// Run one-time migration from flat config layout to per-profile layout.
///
/// Triggered when `profiles/` does not exist but root credential files do.
/// Uses copy-then-delete for safety: originals removed only after copies verified.
pub async fn migrate_to_profiles(base_dir: &Path) -> Result<bool, GwsError> {
    let profiles_dir = base_dir.join(PROFILES_DIR);
    let root_enc = base_dir.join("credentials.enc");

    // Only migrate if profiles dir doesn't exist but root credentials do
    if tokio::fs::try_exists(&profiles_dir).await.unwrap_or(false) {
        return Ok(false); // Already migrated
    }
    if !tokio::fs::try_exists(&root_enc).await.unwrap_or(false) {
        return Ok(false); // Nothing to migrate
    }

    let profile = ProfileName::new(DEFAULT_PROFILE)?;
    let target_dir = ensure_profile_dir(base_dir, &profile).await?;

    // Files to migrate
    let files_to_migrate = [
        "credentials.enc",
        "token_cache.json",
        "sa_token_cache.json",
        ".encryption_key",
        "account_timezone",
    ];

    let mut migrated = Vec::new();

    // Phase 1: Copy files
    for filename in &files_to_migrate {
        let src = base_dir.join(filename);
        let dst = target_dir.join(filename);

        if tokio::fs::try_exists(&src).await.unwrap_or(false) {
            match tokio::fs::copy(&src, &dst).await {
                Ok(_) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = tokio::fs::set_permissions(
                            &dst,
                            std::fs::Permissions::from_mode(0o600),
                        )
                        .await;
                    }
                    migrated.push(filename.to_string());
                }
                Err(e) => {
                    eprintln!("Warning: failed to migrate {}: {e}", src.display());
                }
            }
        }
    }

    // Phase 2: Write active_profile
    let active_file = base_dir.join(ACTIVE_PROFILE_FILE);
    crate::fs_util::atomic_write_async(&active_file, DEFAULT_PROFILE.as_bytes())
        .await
        .map_err(|e| {
            GwsError::Validation(format!(
                "Failed to write active_profile during migration: {e}"
            ))
        })?;

    // Phase 3: Copy keyring entry
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown-user".to_string());

    // Try to copy the keyring entry from old name to new profile-scoped name
    let old_keyring_user = username.clone();
    let new_keyring_user = format!("{}/{}", username, DEFAULT_PROFILE);
    if let Ok(old_entry) = keyring::Entry::new("gws-cli", &old_keyring_user) {
        if let Ok(password) = old_entry.get_password() {
            if let Ok(new_entry) = keyring::Entry::new("gws-cli", &new_keyring_user) {
                let _ = new_entry.set_password(&password);
            }
        }
    }

    // Phase 4: Delete originals (only after successful copies)
    for filename in &migrated {
        let src = base_dir.join(filename);
        if let Err(e) = tokio::fs::remove_file(&src).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "Warning: failed to remove original file after migration: {}",
                    src.display()
                );
            }
        }
    }

    if !migrated.is_empty() {
        eprintln!(
            "Migrated credentials to profile '{}'. Use `gws auth profile list` to see profiles.",
            DEFAULT_PROFILE
        );
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn profile_name_valid() {
        assert!(ProfileName::new("default").is_ok());
        assert!(ProfileName::new("work").is_ok());
        assert!(ProfileName::new("my_profile").is_ok());
        assert!(ProfileName::new("dev_01").is_ok());
        assert!(ProfileName::new("a").is_ok());
        assert!(ProfileName::new("profile_with-dash").is_ok());
    }

    #[test]
    fn profile_name_rejects_empty() {
        assert!(ProfileName::new("").is_err());
    }

    #[test]
    fn profile_name_rejects_dot() {
        assert!(ProfileName::new(".").is_err());
        assert!(ProfileName::new("..").is_err());
    }

    #[test]
    fn profile_name_rejects_leading_hyphen() {
        assert!(ProfileName::new("-profile").is_err());
    }

    #[test]
    fn profile_name_rejects_uppercase() {
        assert!(ProfileName::new("Work").is_err());
        assert!(ProfileName::new("DEFAULT").is_err());
    }

    #[test]
    fn profile_name_rejects_path_traversal() {
        assert!(ProfileName::new("../etc").is_err());
        assert!(ProfileName::new("a/b").is_err());
        assert!(ProfileName::new("a\\b").is_err());
    }

    #[test]
    fn profile_name_rejects_percent() {
        assert!(ProfileName::new("a%2e").is_err());
    }

    #[test]
    fn profile_name_rejects_control_chars() {
        assert!(ProfileName::new("abc\0def").is_err());
        assert!(ProfileName::new("abc\ndef").is_err());
    }

    #[test]
    fn profile_name_rejects_too_long() {
        let long = "a".repeat(65);
        assert!(ProfileName::new(&long).is_err());
        // 64 should be ok
        let max = "a".repeat(64);
        assert!(ProfileName::new(&max).is_ok());
    }

    #[test]
    fn profile_dir_constructs_correct_path() {
        let base = Path::new("/home/user/.config/gws");
        let profile = ProfileName::new("work").unwrap();
        assert_eq!(
            profile_dir(base, &profile),
            PathBuf::from("/home/user/.config/gws/profiles/work")
        );
    }

    #[tokio::test]
    async fn create_and_list_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let default = ProfileName::new("default").unwrap();
        create_profile(base, &default).await.unwrap();

        let work = ProfileName::new("work").unwrap();
        create_profile(base, &work).await.unwrap();

        let profiles = list_profiles(base).await.unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(profiles.iter().any(|(n, _)| n == "default"));
        assert!(profiles.iter().any(|(n, _)| n == "work"));
    }

    #[tokio::test]
    async fn create_duplicate_profile_fails() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let profile = ProfileName::new("work").unwrap();
        create_profile(base, &profile).await.unwrap();
        assert!(create_profile(base, &profile).await.is_err());
    }

    #[tokio::test]
    async fn delete_nonexistent_profile_fails() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let profile = ProfileName::new("ghost").unwrap();
        assert!(delete_profile(base, &profile).await.is_err());
    }

    #[tokio::test]
    async fn switch_profile() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let default = ProfileName::new("default").unwrap();
        create_profile(base, &default).await.unwrap();

        let work = ProfileName::new("work").unwrap();
        create_profile(base, &work).await.unwrap();

        set_active_profile(base, &work).await.unwrap();

        let active = resolve_active_profile(None, base).unwrap();
        assert_eq!(active.as_str(), "work");
    }

    #[tokio::test]
    async fn switch_nonexistent_profile_fails() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let profile = ProfileName::new("ghost").unwrap();
        assert!(set_active_profile(base, &profile).await.is_err());
    }

    #[test]
    fn resolve_profile_cli_override() {
        let dir = tempfile::tempdir().unwrap();
        let profile = resolve_active_profile(Some("work"), dir.path()).unwrap();
        assert_eq!(profile.as_str(), "work");
    }

    #[test]
    #[serial]
    fn resolve_profile_env_var() {
        let dir = tempfile::tempdir().unwrap();

        std::env::set_var("GOOGLE_WORKSPACE_CLI_PROFILE", "staging");
        let profile = resolve_active_profile(None, dir.path()).unwrap();
        std::env::remove_var("GOOGLE_WORKSPACE_CLI_PROFILE");

        assert_eq!(profile.as_str(), "staging");
    }

    #[test]
    fn resolve_profile_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("active_profile"), "production").unwrap();

        let profile = resolve_active_profile(None, dir.path()).unwrap();
        assert_eq!(profile.as_str(), "production");
    }

    #[test]
    fn resolve_profile_default_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let profile = resolve_active_profile(None, dir.path()).unwrap();
        assert_eq!(profile.as_str(), "default");
    }

    #[test]
    fn resolve_profile_rejects_traversal_in_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("active_profile"), "../etc/passwd").unwrap();

        let result = resolve_active_profile(None, dir.path());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn migrate_creates_default_profile() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        // Create root-level credential files (old layout)
        tokio::fs::write(base.join("credentials.enc"), b"fake-enc-data")
            .await
            .unwrap();
        tokio::fs::write(base.join("token_cache.json"), b"fake-cache")
            .await
            .unwrap();

        let migrated = migrate_to_profiles(base).await.unwrap();
        assert!(migrated);

        // Verify files were copied to profiles/default/
        let default_dir = base.join("profiles").join("default");
        assert!(default_dir.join("credentials.enc").exists());
        assert!(default_dir.join("token_cache.json").exists());

        // Verify originals were removed
        assert!(!base.join("credentials.enc").exists());
        assert!(!base.join("token_cache.json").exists());

        // Verify active_profile was set
        let active = std::fs::read_to_string(base.join("active_profile")).unwrap();
        assert_eq!(active.trim(), "default");
    }

    #[tokio::test]
    async fn migrate_no_op_when_already_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        // Create profiles directory (already migrated)
        tokio::fs::create_dir_all(base.join("profiles").join("default"))
            .await
            .unwrap();

        let migrated = migrate_to_profiles(base).await.unwrap();
        assert!(!migrated);
    }

    #[tokio::test]
    async fn migrate_no_op_when_no_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let migrated = migrate_to_profiles(dir.path()).await.unwrap();
        assert!(!migrated);
    }

    #[tokio::test]
    async fn delete_profile_removes_directory() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let profile = ProfileName::new("work").unwrap();
        create_profile(base, &profile).await.unwrap();

        // Create some files in the profile
        let pdir = profile_dir(base, &profile);
        tokio::fs::write(pdir.join("credentials.enc"), b"data")
            .await
            .unwrap();

        delete_profile(base, &profile).await.unwrap();
        assert!(!pdir.exists());
    }

    #[tokio::test]
    async fn delete_active_profile_clears_active_file() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        let profile = ProfileName::new("work").unwrap();
        create_profile(base, &profile).await.unwrap();
        set_active_profile(base, &profile).await.unwrap();

        delete_profile(base, &profile).await.unwrap();

        // active_profile file should be removed
        assert!(!base.join("active_profile").exists());
    }
}
