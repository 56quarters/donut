//
//

use trust_dns::client::{Client, SyncClient};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::udp::UdpClientConnection;

use crate::types::{DohAnswer, DohQuestion, DohRequest, DohResult, DonutResult};

pub struct UdpResolverBackend {
    client: SyncClient<UdpClientConnection>,
}

impl UdpResolverBackend {
    pub fn new(client: SyncClient<UdpClientConnection>) -> Self {
        UdpResolverBackend { client }
    }

    pub async fn resolve(&self, request: &DohRequest) -> DonutResult<DohResult> {
        let name = Name::from_utf8(&request.name)?;
        let kind = RecordType::from(request.kind);
        let class = DNSClass::IN;

        //let (bg, client) = self.client.new_future();
        // TODO: how do we actually use trust-dns async?
        let res = self.client.query(&name, class, kind)?;
        let question = DohQuestion::new(&request.name, request.kind);
        let answers: Vec<DohAnswer> = res
            .answers()
            .iter()
            .map(|record| {
                let data = match record.rdata() {
                    RData::A(v) => v.to_string(),
                    RData::AAAA(v) => v.to_string(),
                    RData::CNAME(v) => v.to_string(),
                    _ => panic!("Unexpected result: {:?}", record),
                };

                DohAnswer::new(
                    record.name().to_utf8(),
                    u16::from(record.record_type()),
                    record.ttl(),
                    data,
                )
            })
            .collect();

        Ok(DohResult::new(
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
