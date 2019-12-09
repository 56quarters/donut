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
use trust_dns::client::{Client, SyncClient};
use trust_dns::op::DnsResponse;
use trust_dns::rr::DNSClass;
use trust_dns::udp::UdpClientConnection;

///
///
///
// Note that we're using the synchronous client instead of the ClientFuture. This is
// because the version of trust_dns we're using is built on the futures crate while
// Hyper (and the Tokio version it pulls in) is built on std::future. This means we
// can't actually run the DNS client future (the "bg" future it returns) on the same
// Tokio executor that everything else uses. So we just make this wrapper async instead.
pub struct UdpResolver {
    backend: SyncClient<UdpClientConnection>,
}

impl UdpResolver {
    ///
    ///
    ///
    pub fn new(backend: SyncClient<UdpClientConnection>) -> Self {
        UdpResolver { backend }
    }

    ///
    ///
    ///
    pub fn resolve(&self, req: &DohRequest) -> DonutResult<DnsResponse> {
        Ok(self.backend.query(&req.name, DNSClass::IN, req.kind)?)
    }
}

impl std::fmt::Debug for UdpResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "UdpResolver {{ ... }}")
    }
}

pub struct TlsResolver;
