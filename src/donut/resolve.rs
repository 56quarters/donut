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
use trust_dns_client::proto::xfer::DnsMultiplexerSerialResponse;
use trust_dns_client::rr::DNSClass;

///
///
///
#[derive(Debug, Clone)]
pub struct MultiTransportResolver {
    repr: ResolverRepr,
}

impl MultiTransportResolver {
    ///
    ///
    ///
    pub async fn resolve(&self, req: DohRequest) -> DonutResult<DnsResponse> {
        // Note that we're cloning the client here because the query method takes a mutable
        // reference to self. Our options are to either guard the client with a mutex or to
        // use a new instance for each request. Turns out that cloning the instance is actually
        // faster than using a mutex and scales better if requests starting timing out.
        let res = match self.repr {
            ResolverRepr::UdpBackend(ref client) => {
                let mut copy = client.clone();
                copy.query(req.name.clone(), DNSClass::IN, req.kind).await?
            }
            ResolverRepr::TcpBackend(ref client) => {
                let mut copy = client.clone();
                copy.query(req.name.clone(), DNSClass::IN, req.kind).await?
            }
        };

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

impl From<AsyncClient<UdpResponse>> for MultiTransportResolver {
    fn from(client: AsyncClient<UdpResponse>) -> Self {
        MultiTransportResolver {
            repr: ResolverRepr::UdpBackend(client),
        }
    }
}

impl From<AsyncClient<DnsMultiplexerSerialResponse>> for MultiTransportResolver {
    fn from(client: AsyncClient<DnsMultiplexerSerialResponse>) -> Self {
        MultiTransportResolver {
            repr: ResolverRepr::TcpBackend(client),
        }
    }
}

///
///
///
// Manually implementing dynamic dispatch like a chump because we can't use `async`
// in a trait without a crate that makes the type signatures really complicated and I
// still don't understand what Pin<T> means.
#[derive(Clone)]
enum ResolverRepr {
    UdpBackend(AsyncClient<UdpResponse>),
    TcpBackend(AsyncClient<DnsMultiplexerSerialResponse>),
}

impl std::fmt::Debug for ResolverRepr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ResolverRepr::UdpBackend(_) => write!(f, "ResolverRepr::UdpBackend {{ ... }}"),
            ResolverRepr::TcpBackend(_) => write!(f, "ResolverRepr::TcpBackend {{ ... }}"),
        }
    }
}

