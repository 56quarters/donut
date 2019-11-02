//
//

use crate::types::{DohAnswer, DohQuestion, DohRequest, DohResult, DonutError, DonutResult};
use trust_dns::client::{Client, SyncClient};
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns::udp::UdpClientConnection;

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
                let data = record_to_data(record);
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
        //RData::NAPTR(v) =>  ,
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

///
///
///
// TODO: Any validation. Does trust-dns do this?
pub fn validate_name(name: &str) -> DonutResult<&str> {
    Ok(name)
}

///
///
///
pub fn validate_kind(kind: &str) -> DonutResult<u16> {
    let parsed_type: Option<RecordType> = kind
        // Attempt to parse the input string as a number (1..65535)
        .parse::<u16>()
        .ok()
        .map(|i| RecordType::from(i))
        .and_then(|r| match r {
            // Filter out the "unknown" variant that parsing yields
            RecordType::Unknown(_) => None,
            _ => Some(r),
        })
        // If it wasn't a number, try to parse it as a string (A, AAAA, etc).
        .or_else(|| kind.to_uppercase().parse().ok());

    parsed_type
        .map(|r| u16::from(r))
        .ok_or_else(|| DonutError::InvalidInput)
}
