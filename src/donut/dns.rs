//
//

use crate::types::{DohAnswer, DohQuestion, DohRequest, DohResponse, DonutResult};
use trust_dns::client::{Client, SyncClient};
use trust_dns::rr::{DNSClass, RData, Record};
use trust_dns::udp::UdpClientConnection;

///
///
///
///
///
// Note that we're using the synchronous client instead of the ClientFuture. This is
// because the version of trust_dns we're using is built on the futures crate while
// Hyper (and the Tokio version it pulls in) is built on std::future. This means we
// can't actually run the DNS client future (the "bg" future it returns) on the same
// Tokio executor that everything else uses. So we just make this wrapper async instead.
pub struct UdpResolverBackend {
    client: SyncClient<UdpClientConnection>,
}

impl UdpResolverBackend {
    ///
    ///
    ///
    pub fn new(client: SyncClient<UdpClientConnection>) -> Self {
        UdpResolverBackend { client }
    }

    ///
    ///
    ///
    pub async fn resolve(&self, request: &DohRequest) -> DonutResult<DohResponse> {
        let res = self.client.query(&request.name, DNSClass::IN, request.kind)?;
        let question = DohQuestion::new(request.name.to_utf8(), u16::from(request.kind));
        let answers: Vec<DohAnswer> = res
            .answers()
            .iter()
            .map(|record| {
                let data = record_to_data(record);
                DohAnswer::new(
                    record.name().to_utf8(),
                    u16::from(record.record_type()),
                    record.ttl(),
                    data,
                )
            })
            .collect();

        Ok(DohResponse::new(
            u16::from(res.response_code()),
            res.truncated(),
            res.recursion_desired(),
            res.recursion_available(),
            false,
            true,
            vec![question],
            answers,
        ))
    }
}

impl std::fmt::Debug for UdpResolverBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "UdpResolverBackend {{ ... }}")
    }
}

///
///
///
fn record_to_data(record: &Record) -> String {
    match record.rdata() {
        RData::A(v) => v.to_string(),
        RData::AAAA(v) => v.to_string(),
        RData::ANAME(v) => v.to_string(),
        //RData::CAA(v) => ,
        RData::CNAME(v) => v.to_string(),
        RData::MX(v) => format!("{} {}", v.preference(), v.exchange()),
        //RData::NAPTR(v) => ,
        RData::NS(v) => v.to_string(),
        //RData::NULL(v) =>  ,
        //RData::OPENPGPKEY(v) => ,
        //RData::OPT(v) => ,
        RData::PTR(v) => v.to_string(),
        //RData::SOA(v) => ,
        RData::SRV(v) => format!("{} {} {} {}", v.priority(), v.weight(), v.port(), v.target()),
        //RData::SSHFP(v) => ,
        //RData::TLSA(v) => ,
        //RData::TXT(v) => ,
        _ => panic!("Unexpected result: {:?}", record),
    }
}
