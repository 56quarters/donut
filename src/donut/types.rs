// Donut - DNS over HTTPS server
//
// Copyright 2019 Nick Pillitteri
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

use base64::DecodeError;
use failure::Fail;
use serde_json::Error as SerdeError;
use std::io;
use trust_dns::error::{ClientError as DnsClientError, ParseError as DnsParseError};
use trust_dns::proto::error::ProtoError as DnsProtoError;
use trust_dns::rr::{Name, RecordType};

pub type DonutResult<T> = Result<T, DonutError>;

#[derive(Debug, Fail)]
pub enum DonutError {
    #[fail(display = "io error: {}", _0)]
    IoError(#[cause] io::Error),

    #[fail(display = "base64 error: {}", _0)]
    Base64Error(#[cause] DecodeError),

    #[fail(display = "dns client error: {}", _0)]
    DnsClientError(#[cause] DnsClientError),

    #[fail(display = "dns parse error: {}", _0)]
    DnsParseError(#[cause] DnsParseError),

    #[fail(display = "invalid input: {}", _0)]
    InvalidInputStr(&'static str),

    #[fail(display = "invalid input: {}", _0)]
    InvalidInputString(String),

    #[fail(display = "serialization error: {}", _0)]
    SerializationError(#[cause] SerdeError),
}

impl From<io::Error> for DonutError {
    fn from(e: io::Error) -> Self {
        DonutError::IoError(e)
    }
}

impl From<DecodeError> for DonutError {
    fn from(e: DecodeError) -> Self {
        DonutError::Base64Error(e)
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

// TODO: Support multiple name + type pairs?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohRequest {
    pub name: Name,
    pub kind: RecordType,
    pub checking_disabled: bool,
    pub dnssec_data: bool,
    pub queries: Vec<(Name, RecordType)>,
}

impl DohRequest {
    pub fn new(name: Name, kind: RecordType, checking_disabled: bool, dnssec_data: bool) -> Self {
        DohRequest {
            name,
            kind,
            checking_disabled,
            dnssec_data,
            queries: Vec::new(),
        }
    }
}
