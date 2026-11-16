//! Host-executable Gregorian and timezone rules; never calls Windows APIs.
#[path = "civil.rs"]
mod civil;
#[path = "rules.rs"]
mod rules;

use rules::{Day, Rules, Transition};
#[path = "timezone/environment.rs"]
mod environment;
