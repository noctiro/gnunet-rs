//! Bounded caller-buffer HTTP and official GNUnet v0.29.1 REST contracts.
//! This pure crate opens no HTTP listener, service, key, clock or worker.
#![no_std]
#![forbid(unsafe_code)]
pub mod base64;
pub mod http;
pub mod route;

pub mod contracts;
pub mod text;

pub mod form;
#[cfg(feature = "oidc")]
pub mod oidc;

/// Plain-text representation of the official `/copying` endpoint.
pub const COPYING: &[u8] = b"GNU Affero General Public License version 3 or later. See also: <http://www.gnu.org/licenses/>";
