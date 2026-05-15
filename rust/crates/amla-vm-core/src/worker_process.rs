// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Worker process launch configuration shared by hypervisor backends.

use std::ffi::OsString;
use std::path::PathBuf;

/// Executable used for a hypervisor worker subprocess.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerBinary {
    /// Launch a specific absolute executable path.
    Path(PathBuf),
    /// Launch the current executable.
    ///
    /// Embedders use this for single-binary deployment. The embedding binary
    /// must dispatch the configured role argument to `worker_main()` before
    /// running normal application code.
    CurrentExe,
}

/// Runtime worker subprocess launch configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerProcessConfig {
    binary: WorkerBinary,
    args: Vec<OsString>,
}

impl WorkerProcessConfig {
    /// Launch a specific worker binary path.
    ///
    /// The path must be absolute by the time [`executable_path()`](Self::executable_path)
    /// is used. Relative worker paths are rejected so subprocess backends do
    /// not depend on the caller's current directory or `PATH` lookup.
    #[must_use]
    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self {
            binary: WorkerBinary::Path(path.into()),
            args: Vec::new(),
        }
    }

    /// Launch the current executable with a role argument.
    #[must_use]
    pub fn current_exe(role_arg: impl Into<OsString>) -> Self {
        Self {
            binary: WorkerBinary::CurrentExe,
            args: vec![role_arg.into()],
        }
    }

    /// Add an argument passed to the worker process.
    #[must_use]
    pub fn with_arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Worker binary selector.
    #[must_use]
    pub const fn binary(&self) -> &WorkerBinary {
        &self.binary
    }

    /// Worker process arguments.
    #[must_use]
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// Resolve the executable path to pass to process spawning.
    ///
    /// # Errors
    ///
    /// Returns an IO error if the current executable path cannot be resolved or
    /// a configured worker path is empty or relative.
    pub fn executable_path(&self) -> std::io::Result<PathBuf> {
        match &self.binary {
            WorkerBinary::Path(path) => {
                if path.as_os_str().is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "worker binary path must not be empty",
                    ));
                }
                if !path.is_absolute() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "worker binary path must be absolute",
                    ));
                }
                Ok(path.clone())
            }
            WorkerBinary::CurrentExe => std::env::current_exe(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_path_rejects_relative_worker_binary() {
        let err = WorkerProcessConfig::path("amla-kvm-worker")
            .executable_path()
            .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("absolute"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn executable_path_accepts_absolute_worker_binary() {
        let config = WorkerProcessConfig::path("/usr/bin/amla-kvm-worker");

        assert_eq!(
            config.executable_path().unwrap(),
            PathBuf::from("/usr/bin/amla-kvm-worker")
        );
    }
}
