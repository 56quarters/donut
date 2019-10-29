//
//

use failure::Fail;
use serde::Serialize;
use std::io;
use trust_dns::error::{ClientError as DnsClientError, ParseError as DnsParseError};
use trust_dns::proto::error::ProtoError as DnsProtoError;

pub type DonutResult<T> = Result<T, DonutError>;

#[derive(Debug, Fail)]
pub enum DonutError {
    #[fail(display = "{}", _0)]
    IoError(#[cause] io::Error),

    #[fail(display = "{}", _0)]
    DnsClientError(#[cause] DnsClientError),

    #[fail(display = "{}", _0)]
    DnsParseError(#[cause] DnsParseError),
}

impl From<DnsClientError> for DonutError {
    fn from(e: DnsClientError) -> Self {
        DonutError::DnsClientError(e)
    }
}

impl From<DnsParseError> for DonutError {
    fn from(e: DnsParseError) -> Self {
        DonutError::DnsParseError(e)
    }
}

impl From<DnsProtoError> for DonutError {
    fn from(e: DnsProtoError) -> Self {
        DonutError::DnsParseError(DnsParseError::from(e))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct DohRequest {
    pub name: String,
    pub kind: u16,
    pub checking_disabled: bool,
    pub content_type: String,
    pub dnssec_ok: bool,
}

impl DohRequest {
    pub fn new<S1, S2>(name: S1, kind: u16, checking_disabled: bool, content_type: S2, dnssec_ok: bool) -> Self
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
    pub name: String,

    #[serde(rename = "type")]
    pub kind: u16,
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
    pub name: String,

    #[serde(rename = "type")]
    pub kind: u16,

    #[serde(rename = "TTL")]
    pub ttl: u32,

    #[serde(rename = "data")]
    pub data: String,
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
