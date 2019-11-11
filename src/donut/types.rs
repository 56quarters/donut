//
//

use failure::Fail;
use serde::Serialize;
use serde_json::Error as SerdeError;
use std::io;
use trust_dns::error::{ClientError as DnsClientError, ParseError as DnsParseError};
use trust_dns::proto::error::ProtoError as DnsProtoError;
use trust_dns::rr::{Name, RecordType};

pub type DonutResult<T> = Result<T, DonutError>;

#[derive(Debug, Fail)]
pub enum DonutError {
    #[fail(display = "{}", _0)]
    IoError(#[cause] io::Error),

    #[fail(display = "{}", _0)]
    DnsClientError(#[cause] DnsClientError),

    #[fail(display = "{}", _0)]
    DnsParseError(#[cause] DnsParseError),

    #[fail(display = "invalid input: {}", _0)]
    InvalidInputStr(&'static str),

    #[fail(display = "invalid input: {}", _0)]
    InvalidInputString(String),

    #[fail(display = "{}", _0)]
    SerializationError(#[cause] SerdeError),
}

impl From<io::Error> for DonutError {
    fn from(e: io::Error) -> Self {
        DonutError::IoError(e)
    }
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

impl From<SerdeError> for DonutError {
    fn from(e: SerdeError) -> Self {
        DonutError::SerializationError(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohRequest {
    pub name: Name,
    pub kind: RecordType,
    pub checking_disabled: bool,
    pub dnssec_data: bool,
}

impl DohRequest {
    pub fn new(name: Name, kind: RecordType, checking_disabled: bool, dnssec_data: bool) -> Self {
        DohRequest {
            name,
            kind,
            checking_disabled,
            dnssec_data,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct JsonQuestion {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "type")]
    pub kind: u16,
}

impl JsonQuestion {
    pub fn new<S>(name: S, kind: u16) -> Self
    where
        S: Into<String>,
    {
        JsonQuestion {
            name: name.into(),
            kind,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct JsonAnswer {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "type")]
    pub kind: u16,

    #[serde(rename = "TTL")]
    pub ttl: u32,

    #[serde(rename = "data")]
    pub data: String,
}

impl JsonAnswer {
    pub fn new<S1, S2>(name: S1, kind: u16, ttl: u32, data: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        JsonAnswer {
            name: name.into(),
            kind,
            ttl,
            data: data.into(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct JsonResponse {
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
    questions: Vec<JsonQuestion>,

    #[serde(rename = "Answer")]
    answers: Vec<JsonAnswer>,
}

impl JsonResponse {
    pub fn new(
        status: u16,
        truncated: bool,
        recursion_desired: bool,
        recursion_available: bool,
        all_validated: bool,
        checking_disabled: bool,
        questions: Vec<JsonQuestion>,
        answers: Vec<JsonAnswer>,
    ) -> Self {
        JsonResponse {
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
