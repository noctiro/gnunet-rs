use super::{Error, NativeFailure};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BUSY, ERROR_FILE_NOT_FOUND, ERROR_NOT_READY, ERROR_SHARING_VIOLATION,
};

#[test]
fn exclusive_open_conflict_allows_only_a_fresh_device_attempt() {
    let error = Error::Native(NativeFailure {
        operation: "CreateFileW",
        code: ERROR_SHARING_VIOLATION,
    });
    assert!(error.is_start_pending());
    assert!(!error.is_policy_loss());
    for operation in [
        "DeviceIoControl(IOCTL_START)",
        "DeviceIoControl(IOCTL_SET_EVENT)",
        "DeviceIoControl(IOCTL_STOP)",
        "ReadFile",
        "WriteFile",
        "CloseHandle(packet device)",
    ] {
        let observed = Error::Native(NativeFailure {
            operation,
            code: ERROR_SHARING_VIOLATION,
        });
        assert!(!observed.is_start_pending());
        assert!(!observed.is_policy_loss());
    }
}

#[test]
fn readiness_refuses_missing_access_and_unsupported_operation_failures() {
    for operation in ["CreateFileW", "DeviceIoControl(IOCTL_START)"] {
        for code in [ERROR_BUSY, ERROR_NOT_READY] {
            assert!(Error::Native(NativeFailure { operation, code }).is_start_pending());
        }
        for code in [ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND] {
            assert!(!Error::Native(NativeFailure { operation, code }).is_start_pending());
        }
    }
    assert!(
        !Error::Native(NativeFailure {
            operation: "DeviceIoControl(IOCTL_SET_EVENT)",
            code: ERROR_NOT_READY,
        })
        .is_start_pending()
    );
}

#[test]
fn only_a_not_ready_write_reports_write_unavailability() {
    let stale = Error::Native(NativeFailure {
        operation: "WriteFile",
        code: ERROR_NOT_READY,
    });
    assert!(stale.is_write_not_ready());
    assert!(!stale.is_policy_loss());
    for (operation, code) in [
        ("WriteFile", ERROR_ACCESS_DENIED),
        ("WriteFile", ERROR_BUSY),
        ("ReadFile", ERROR_NOT_READY),
        ("DeviceIoControl(IOCTL_COMPLETION)", ERROR_NOT_READY),
    ] {
        assert!(!Error::Native(NativeFailure { operation, code }).is_write_not_ready());
    }
}
