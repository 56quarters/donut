use crate::types::{DohRequest, DonutResult, JsonAnswer, JsonQuestion, JsonResponse};
use trust_dns::op::DnsResponse;
use trust_dns::proto::serialize::binary::BinEncodable;
use trust_dns::rr::{RData, Record};

///
///
///
pub struct ResponseEncoderJson;

impl ResponseEncoderJson {
    ///
    ///
    ///
    pub fn new() -> Self {
        ResponseEncoderJson
    }

    ///
    ///
    ///
    pub fn encode(&self, req: &DohRequest, res: &DnsResponse) -> DonutResult<Vec<u8>> {
        let question = JsonQuestion::new(req.name.to_utf8(), u16::from(req.kind));
        let answers: Vec<JsonAnswer> = res
            .answers()
            .iter()
            .map(|record| {
                let data = Self::record_to_data(record);
                JsonAnswer::new(
                    record.name().to_utf8(),
                    u16::from(record.record_type()),
                    record.ttl(),
                    data,
                )
            })
            .collect();

        Ok(serde_json::to_vec(&JsonResponse::new(
            u16::from(res.response_code()),
            res.truncated(),
            res.recursion_desired(),
            res.recursion_available(),
            false,
            true,
            vec![question],
            answers,
        ))?)
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
}

///
///
///
#[derive(Default, Debug, Clone)]
pub struct ResponseEncoderWire;

impl ResponseEncoderWire {
    ///
    ///
    ///
    pub fn new() -> Self {
        ResponseEncoderWire
    }

    ///
    ///
    ///
    pub fn encode(&self, req: &DohRequest, res: &DnsResponse) -> DonutResult<Vec<u8>> {
        Ok(res.to_bytes()?)
    }
}
