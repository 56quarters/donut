use crate::types::{DohRequest, DonutError, DonutResult};
use hyper::{Body, Request};
use std::collections::HashMap;
use trust_dns::proto::op::Message;
use trust_dns::proto::serialize::binary::BinDecodable;
use trust_dns::proto::xfer::{DnsRequest, DnsRequestOptions};
use trust_dns::rr::{Name, RecordType};

#[derive(Default, Debug, Clone)]
pub struct RequestParserJsonGet;

impl RequestParserJsonGet {
    pub fn new() -> Self {
        RequestParserJsonGet
    }

    pub fn parse(&self, req: &Request<Body>) -> DonutResult<DohRequest> {
        let qs = req.uri().query().unwrap_or("").to_string();
        let query = url::form_urlencoded::parse(qs.as_bytes());
        let params: HashMap<String, String> = query.into_owned().collect();

        let name = params
            .get("name")
            .ok_or_else(|| DonutError::InvalidInputStr("name"))
            .and_then(|s| Self::parse_query_name(s))?;
        let kind = params
            .get("type")
            .ok_or_else(|| DonutError::InvalidInputStr("type"))
            .and_then(|s| Self::parse_requery_type(s))?;
        let dnssec_data = params
            .get("do")
            .map(|s| (s == "1" || s.to_lowercase() == "true"))
            .unwrap_or(false);
        let checking_disabled = params
            .get("cd")
            .map(|s| (s == "1" || s.to_lowercase() == "true"))
            .unwrap_or(false);

        Ok(DohRequest::new(name, kind, checking_disabled, dnssec_data))
    }

    ///
    ///
    ///
    fn parse_query_name(name: &str) -> DonutResult<Name> {
        name.parse().map_err(|_| DonutError::InvalidInputStr("name"))
    }

    ///
    ///
    ///
    fn parse_requery_type(kind: &str) -> DonutResult<RecordType> {
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

        parsed_type.ok_or_else(|| DonutError::InvalidInputStr("type"))
    }
}

///
///
///
#[derive(Default, Debug, Clone)]
pub struct RequestParserWireGet;

impl RequestParserWireGet {
    ///
    ///
    ///
    pub fn new() -> Self {
        RequestParserWireGet
    }

    ///
    ///
    ///
    pub fn parse(&self, req: &Request<Body>) -> DonutResult<DohRequest> {
        let qs = req.uri().query().unwrap_or("").to_string();
        let query = url::form_urlencoded::parse(qs.as_bytes());
        let params: HashMap<String, String> = query.into_owned().collect();

        let request_bytes = params
            .get("dns")
            .ok_or_else(|| DonutError::InvalidInputStr("dns"))
            .and_then(|d| base64::decode(d).map_err(|e| DonutError::from(e)))
            .and_then(|b| Message::from_bytes(&b).map_err(|e| DonutError::from(e)))?;

        unimplemented!();
    }
}

///
///
///
#[derive(Default, Debug, Clone)]
pub struct RequestParserWirePost;

impl RequestParserWirePost {
    ///
    ///
    ///
    pub fn new() -> Self {
        RequestParserWirePost
    }

    ///
    ///
    ///
    pub fn parse(&self, req: &Request<Body>) -> DonutResult<DohRequest> {
        unimplemented!();
    }
}
