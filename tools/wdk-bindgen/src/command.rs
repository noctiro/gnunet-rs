use crate::{Result, invalid, receipt};
use serde_json::json;
use std::{
    path::Path,
    process::{Command, Output, Stdio},
};

pub fn run(directory: &Path, step: &str, command: &mut Command) -> Result<Output> {
    let output = command.stdin(Stdio::null()).output()?;
    let arguments: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy())
        .collect();
    receipt::write(
        &directory.join(format!("{step}.json")),
        &json!({
            "program": command.get_program().to_string_lossy(), "arguments": arguments,
            "exit_code": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr),
        }),
    )?;
    if !output.status.success() {
        return Err(invalid(format!("{step} failed; see {}", directory.display())).into());
    }
    Ok(output)
}
