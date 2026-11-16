//! Repository surface, storage observations and selected native implementation.
mod native;
mod repository;
mod retention;
pub use repository::Repository;
pub use retention::Insert;
pub use retention::Retention;

#[cfg(test)]
mod tests;
