//
//

mod dns;
mod types;

pub use crate::dns::UdpResolverBackend;
pub use crate::types::{DohAnswer, DohQuestion, DohRequest, DohResult};
