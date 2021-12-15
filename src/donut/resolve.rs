// Donut - DNS over HTTPS server
//
// Copyright 2019 Nick Pillitteri
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

use crate::types::{DohRequest, DonutResult};
use std::fmt;
use tracing::{event, Level};
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::DNSClass;

/// Facade over a Trust DNS `AsyncClient` instance (UDP).
///
/// Note that this struct is thread safe but does not implement `Clone`. It is meant to be
/// used as part of a reference counted (`Arc`) context object that is shared between all
/// requests, being handled on various threads.
pub struct UdpResolver {
    client: AsyncClient,
}

impl UdpResolver {
    pub fn new(client: AsyncClient) -> Self {
        UdpResolver { client }
    }

    pub async fn resolve(&self, req: DohRequest) -> DonutResult<DnsResponse> {
        // Note that we clone the client here because it requires a mutable reference and
        // cloning is the simplest and way to do that (and it's reasonably performant).
        let mut client = self.client.clone();
        let res = client.query(req.name.clone(), DNSClass::IN, req.kind).await?;
        let code = res.response_code();

        event!(
            target: "donut_lookup",
            Level::INFO,
            name = %req.name,
            kind = %req.kind,
            results = res.answers().len(),
            response = u16::from(code),
            response_msg = %code,
        );

        Ok(res)
    }
}

impl fmt::Debug for UdpResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UdpResolver {{ client: AsyncClient(...) }}")
    }
}
