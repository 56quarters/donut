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
use async_trait::async_trait;
use std::fmt;
use tracing::{event, Level};
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::proto::udp::UdpResponse;
use trust_dns_client::proto::xfer::DnsMultiplexerSerialResponse;
use trust_dns_client::rr::DNSClass;

/// Facade over a Trust DNS `AsyncClient` instance (UDP or TCP).
///
/// Used to abstract the type of the underlying transport used by the `AsyncClient` so
/// that we can use the same code for making the request via `MultiTransportResolver`.
#[async_trait]
trait AsyncClientAdapter: Send + Sync {
    async fn resolve(&self, req: DohRequest) -> DonutResult<DnsResponse>;
}

/// Wrap an `AsyncClient` instance that uses UDP transport.
struct UdpAsyncClientAdapter(AsyncClient<UdpResponse>);

#[async_trait]
impl AsyncClientAdapter for UdpAsyncClientAdapter {
    async fn resolve(&self, req: DohRequest) -> DonutResult<DnsResponse> {
        // Note that we clone the client here because it requires a mutable reference and
        // cloning is the simplest and way to do that (and it's reasonably performant).
        let mut client = self.0.clone();
        Ok(client.query(req.name, DNSClass::IN, req.kind).await?)
    }
}

impl fmt::Debug for UdpAsyncClientAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UdpAsyncClientAdapter(AsyncClient<...>)")
    }
}

/// Wrap an `AsyncClient` instance that uses TCP + TLS transport.
struct TcpAsyncClientAdapter(AsyncClient<DnsMultiplexerSerialResponse>);

#[async_trait]
impl AsyncClientAdapter for TcpAsyncClientAdapter {
    async fn resolve(&self, req: DohRequest) -> DonutResult<DnsResponse> {
        // Note that we clone the client here because it requires a mutable reference and
        // cloning is the simplest and way to do that (and it's reasonably performant).
        let mut client = self.0.clone();
        Ok(client.query(req.name, DNSClass::IN, req.kind).await?)
    }
}

impl fmt::Debug for TcpAsyncClientAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TcpAsyncClientAdapter(AsyncClient<...>)")
    }
}

/// Use an `AsyncClientAdapter` implementation to perform DNS lookups asynchronously.
///
/// Note that this struct is thread safe but does not implement `Clone`. It is meant to be
/// used as part of a reference counted (`Arc`) context object that is shared between all
/// requests, being handled on various threads.
pub struct MultiTransportResolver {
    delegate: Box<dyn AsyncClientAdapter>,
}

impl MultiTransportResolver {
    pub async fn resolve(&self, req: DohRequest) -> DonutResult<DnsResponse> {
        let res = self.delegate.resolve(req.clone()).await?;
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
            delegate: Box::new(UdpAsyncClientAdapter(client)),
        }
    }
}

impl From<AsyncClient<DnsMultiplexerSerialResponse>> for MultiTransportResolver {
    fn from(client: AsyncClient<DnsMultiplexerSerialResponse>) -> Self {
        MultiTransportResolver {
            delegate: Box::new(TcpAsyncClientAdapter(client)),
        }
    }
}

impl fmt::Debug for MultiTransportResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MultiTransportResolver {{ delegate: dyn AsyncClientAdapter(...) }}")
    }
}
