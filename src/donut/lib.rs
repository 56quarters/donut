//
//

mod dns;
mod http;
mod types;

pub use crate::dns::UdpResolverBackend;
pub use crate::http::http_route;
pub use crate::types::{DohAnswer, DohQuestion, DohRequest, DohResult};
