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
    pub async fn resolve(&self, req: &DohRequest) -> DonutResult<DnsResponse> {
        Ok(self.backend.query(&req.name, DNSClass::IN, req.kind)?)
    }
}

impl std::fmt::Debug for UdpResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "UdpResolver {{ ... }}")
    }
}

pub struct TlsResolver;
