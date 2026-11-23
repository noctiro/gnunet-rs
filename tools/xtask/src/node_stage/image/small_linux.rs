//! HiSpark Taurus Linux image inputs.
mod elf;

use super::{ImagePaths, NodePolicy, Result, format_json};
use serde_json::json;
use std::path::Path;

pub(super) const TARGET: &str = "armv7-unknown-linux-musleabi";
pub(super) const PATHS: ImagePaths = ImagePaths {
    executable: "/bin/gnunet-node",
    runtime_root: "/storage/data/",
    config_root: "/etc/",
    required_mount: Some("/storage"),
};

pub(super) fn init(policy: &NodePolicy) -> Result<Vec<u8>> {
    format_json(&json!({
        "jobs": [{
            "name": "post-init",
            "cmds": [
                format!("mkdir {} 0700 {} {}", policy.state, policy.uid, policy.gid),
                format!("mkdir {} 0700 {} {}", policy.ipc, policy.uid, policy.gid),
                "start gnunet-node",
            ],
        }],
        "services": [{
            "name": "gnunet-node",
            "path": policy.arguments,
            "uid": policy.uid,
            "gid": policy.gid,
            "caps": [],
            "once": 1,
            "importance": 0,
        }],
    }))
}

pub(super) fn validate_executable(path: &Path) -> Result<()> {
    elf::validate_file(path).map_err(|error| {
        format!(
            "invalid HiSpark Taurus Linux executable {}: {error}",
            path.display()
        )
        .into()
    })
}
