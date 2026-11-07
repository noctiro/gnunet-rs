//! Independently compile the direct and facade metadata-only SDK boundaries.
//! These functions inspect caller-selected local descriptors; they create no
//! publication task, service client or asynchronous runtime.
#![forbid(unsafe_code)]

#[cfg(feature = "host")]
use fs_host as direct;
#[cfg(feature = "facade")]
use gnunet::fs_host as facade;

/// Inspect through the direct host SDK using its actual public extraction API.
#[cfg(feature = "host")]
pub fn inspect_direct(
    input: &std::path::Path,
    visit: impl FnMut(direct::extraction::ExtractedObject) -> Result<(), direct::extraction::Error>,
) -> Result<direct::extraction::InspectionReport, Box<direct::extraction::InspectionFailure>> {
    direct::extraction::inspect_with_metadata(
        input,
        direct::extraction::Limits::default(),
        direct::extraction::Policy::default(),
        direct::extraction::MetadataSettings::default(),
        |_| direct::Control::Continue,
        visit,
    )
}

/// Inspect through the facade using the same actual public extraction API.
#[cfg(feature = "facade")]
pub fn inspect_facade(
    input: &std::path::Path,
    visit: impl FnMut(facade::extraction::ExtractedObject) -> Result<(), facade::extraction::Error>,
) -> Result<facade::extraction::InspectionReport, Box<facade::extraction::InspectionFailure>> {
    facade::extraction::inspect_with_metadata(
        input,
        facade::extraction::Limits::default(),
        facade::extraction::Policy::default(),
        facade::extraction::MetadataSettings::default(),
        |_| facade::Control::Continue,
        visit,
    )
}
