use serde::Serialize;
use std::net::ToSocketAddrs;

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct DohRequest {
    name: String,
    kind: u32,
    checking_disabled: bool,
    content_type: String,
    dnssec_ok: bool,
}

impl DohRequest {
    pub fn new<S>(
        name: S,
        kind: u32,
        checking_disabled: bool,
        content_type: S,
        dnssec_ok: bool,
    ) -> Self
    where
        S: Into<String>,
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
    kind: u32,
}

impl DohQuestion {
    pub fn new<S>(name: S, kind: u32) -> Self
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
    kind: u32,

    #[serde(rename = "TTL")]
    ttl: u32,

    #[serde(rename = "data")]
    data: String,
}

impl DohAnswer {
    pub fn new<S>(name: S, kind: u32, ttl: u32, data: S) -> Self
    where
        S: Into<String>,
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
    status: u32,

    #[serde(rename = "TC")]
    truncated: bool,

    #[serde(rename = "RD")]
    recursive_desired: bool,

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
        status: u32,
        truncated: bool,
        recursive_desired: bool,
        recursion_available: bool,
        all_validated: bool,
        checking_disabled: bool,
        questions: Vec<DohQuestion>,
        answers: Vec<DohAnswer>,
    ) -> Self {
        DohResult {
            status,
            truncated,
            recursive_desired,
            recursion_available,
            all_validated,
            checking_disabled,
            questions,
            answers,
        }
    }
}

pub fn lookup_from_system(request: &DohRequest) -> DohResult {
    let addr = request.name.to_socket_addrs().unwrap().next().unwrap();
    println!("Addr: {:?}", addr.ip().to_string());
    DohResult::default()
}

pub fn lookup_from_dns_udp(request: &DohRequest) -> DohResult {
    unimplemented!();
}

pub fn lookup_from_dns_tls(request: &DohRequest) -> DohResult {
    unimplemented!();
}
