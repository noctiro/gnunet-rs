use super::{Capacity, JobClass};

#[test]
fn minimum_capacity_keeps_sync_and_dependency_read_distinct() {
    let mut capacity = Capacity {
        limit: 4,
        ordinary: 2,
        sync: 0,
        dependency: 0,
        reserved: 0,
    };
    assert!(!capacity.available(JobClass::Ordinary));
    assert!(capacity.available(JobClass::Sync));
    assert!(capacity.available(JobClass::Dependency));
    capacity.sync = 1;
    assert!(!capacity.available(JobClass::Sync));
    assert!(capacity.available(JobClass::Dependency));
    capacity.dependency = 1;
    assert!(!capacity.available(JobClass::Dependency));
    capacity.dependency = 0;
    assert!(capacity.available(JobClass::Dependency));
    assert!(!capacity.available(JobClass::Ordinary));
}

#[test]
fn high_level_limits_preserve_two_job_close_before_any_io() {
    let mut limits = crate::Limits {
        operations: 3,
        ..crate::Limits::default()
    };
    assert_eq!(
        limits.validate::<65524>(),
        Err(gnunet_types::Error::InvalidInput)
    );
    limits.operations = 4;
    limits.core.operations_per_room = 3;
    assert_eq!(
        limits.validate::<65524>(),
        Err(gnunet_types::Error::InvalidInput)
    );
    limits.core.operations_per_room = 4;
    assert_eq!(limits.validate::<65524>(), Ok(()));
}

#[test]
fn ordinary_reservations_cannot_borrow_protocol_credit() {
    let capacity = Capacity {
        limit: 5,
        ordinary: 2,
        sync: 0,
        dependency: 0,
        reserved: 1,
    };
    assert_eq!(capacity.ordinary_free(), 0);
    assert!(capacity.available(JobClass::Sync));
    assert!(capacity.available(JobClass::Dependency));
}
