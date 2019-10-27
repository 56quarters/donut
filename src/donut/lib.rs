use serde::Serialize;
use std::net::ToSocketAddrs;
use trust_dns::op::ResponseCode;
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct DohRequest {
    name: String,
    kind: u16,
    checking_disabled: bool,
    content_type: String,
    dnssec_ok: bool,
}

impl DohRequest {
    pub fn new<S1, S2>(
        name: S1,
        kind: u16,
        checking_disabled: bool,
        content_type: S2,
        dnssec_ok: bool,
    ) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        DohRequest {
            name: name.into(),
            kind,
            checking_disabled,
            content_type: content_type.into(),
            dnssec_ok,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct DohQuestion {
    #[serde(rename = "name")]
    name: String,

    #[serde(rename = "type")]
    kind: u16,
}

impl DohQuestion {
    pub fn new<S>(name: S, kind: u16) -> Self
    where
        S: Into<String>,
    {
        DohQuestion {
            name: name.into(),
            kind,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct DohAnswer {
    #[serde(rename = "name")]
    name: String,

    #[serde(rename = "type")]
    kind: u16,

    #[serde(rename = "TTL")]
    ttl: u32,

    #[serde(rename = "data")]
    data: String,
}

impl DohAnswer {
    pub fn new<S1, S2>(name: S1, kind: u16, ttl: u32, data: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        DohAnswer {
            name: name.into(),
            kind,
            ttl,
            data: data.into(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct DohResult {
    #[serde(rename = "Status")]
    status: u16,

    #[serde(rename = "TC")]
    truncated: bool,

    #[serde(rename = "RD")]
    recursion_desired: bool,

    #[serde(rename = "RA")]
    recursion_available: bool,

    #[serde(rename = "AD")]
    all_validated: bool,

    #[serde(rename = "CD")]
    checking_disabled: bool,

    #[serde(rename = "Question")]
    questions: Vec<DohQuestion>,

    #[serde(rename = "Answer")]
    answers: Vec<DohAnswer>,
}

impl DohResult {
    pub fn new(
        status: u16,
        truncated: bool,
        recursion_desired: bool,
        recursion_available: bool,
        all_validated: bool,
        checking_disabled: bool,
        questions: Vec<DohQuestion>,
        answers: Vec<DohAnswer>,
    ) -> Self {
        DohResult {
            status,
            truncated,
            recursion_desired,
            recursion_available,
            all_validated,
            checking_disabled,
            questions,
            answers,
        }
    }
}

pub fn lookup_from_system(request: &DohRequest) -> DohResult {
    let lookup = (&request.name as &str, 0u16);
    let addr = lookup.to_socket_addrs().unwrap().next().unwrap();
    let question = DohQuestion::new(&request.name, u16::from(RecordType::A));
    let answer = DohAnswer::new(
        &request.name,
        u16::from(RecordType::A),
        300,
        addr.ip().to_string(),
    );

    DohResult::new(
        u16::from(ResponseCode::NoError),
        false,
        true,
        true,
        false,
        false,
        vec![question],
        vec![answer],
    )
}

pub fn lookup_from_dns_udp(request: &DohRequest) -> DohResult {
    unimplemented!();
}

pub fn lookup_from_dns_tls(request: &DohRequest) -> DohResult {
    unimplemented!();
}
