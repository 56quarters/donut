// Donut - DNS over HTTPS server
//
// Copyright 2019 TSH Labs
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
use tracing::{event, Level};
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::proto::udp::UdpResponse;
use trust_dns_client::rr::DNSClass;

///
///
///
pub struct UdpResolver {
    backend: AsyncClient<UdpResponse>,
}

impl UdpResolver {
    ///
    ///
    ///
    pub fn new(backend: AsyncClient<UdpResponse>) -> Self {
        UdpResolver { backend }
    }

    ///
    ///
    ///
    pub async fn resolve(&self, req: DohRequest) -> DonutResult<DnsResponse> {
        // Note that we're cloning the client here because the query method takes a mutable
        // reference to self. Our options are to either guard the client with a mutex or to
        // use a new instance for each request. Turns out that cloning the instance is actually
        // faster than using a mutex and scales better if requests starting timing out.
        let mut client = self.backend.clone();
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

impl std::fmt::Debug for UdpResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "UdpResolver {{ ... }}")
    }
}

pub struct TlsResolver;
