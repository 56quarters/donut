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

use crate::types::DonutResult;
use std::fmt;
use tracing::{event, Level};
use trust_dns_client::client::AsyncClient;
use trust_dns_client::op::DnsResponse;
use trust_dns_client::proto::xfer::DnsRequest;
use trust_dns_client::proto::DnsHandle;

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

    pub async fn resolve(&self, req: DnsRequest) -> DonutResult<DnsResponse> {
        // Note that we clone the client here because it requires a mutable reference and
        // cloning is the simplest and way to do that (and it's reasonably performant).
        let mut client = self.client.clone();
        // Clone the request and use a wrapper so that we can use 'Display' and defer it
        // until needed by the tracing library (e.g. only if log level is INFO or lower).
        let queries = QueryAdapter::new(req.clone());
        let res = client.send(req).await?;
        let code = res.response_code();

        event!(
            target: "donut_lookup",
            Level::INFO,
            queries = %queries,
            results = res.answer_count(),
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

struct QueryAdapter {
    msg: DnsRequest,
}

impl QueryAdapter {
    fn new(msg: DnsRequest) -> Self {
        QueryAdapter { msg }
    }
}

impl fmt::Display for QueryAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, q) in self.msg.queries().iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ",");
            }

            let _ = write!(f, "{{{}}}", q);
        }

        Ok(())
    }
}
