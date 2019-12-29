// Donut - DNS over HTTPS server
//
// Copyright 2019 TSH Labs
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
use failure::{Backtrace, Fail};
use hyper::Error as HyperError;
use serde_json::Error as SerdeError;
use std::fmt;
use trust_dns_client::error::{
    ClientError as DnsClientError, ClientErrorKind as DnsClientErrorKind, ParseError as DnsParseError,
    ParseErrorKind as DnsParseErrorKind,
};
use trust_dns_client::proto::error::{ProtoError as DnsProtoError, ProtoErrorKind as DnsProtoErrorKind};
use trust_dns_client::rr::{Name, RecordType};

pub type DonutResult<T> = Result<T, DonutError>;

#[derive(Debug)]
enum ErrorRepr {
    Base64Error(DecodeError),
    DnsClientError(DnsClientError),
    DnsParseError(DnsParseError),
    DnsProtoError(DnsProtoError),
    HttpError(HyperError),
    SerializationError(SerdeError),
    WithMessageStr(ErrorKind, &'static str),
    WithMessageString(ErrorKind, String),
}

#[derive(PartialEq, Eq, Debug, Hash, Clone, Copy)]
pub enum ErrorKind {
    DnsInternal,
    DnsTimeout,
    InputLength,
    InputParsing,
    InputSerialization,
    HttpInternal,
    OutputSerialization,
}

#[derive(Debug)]
pub struct DonutError {
    repr: ErrorRepr,
}

impl DonutError {
    pub fn kind(&self) -> ErrorKind {
        match self.repr {
            ErrorRepr::Base64Error(_) => ErrorKind::InputSerialization,
            ErrorRepr::DnsClientError(ref e) => match e.kind() {
                DnsClientErrorKind::Timeout => ErrorKind::DnsTimeout,
                _ => ErrorKind::DnsInternal,
            },
            ErrorRepr::DnsParseError(ref e) => match e.kind() {
                DnsParseErrorKind::Timeout => ErrorKind::DnsTimeout,
                _ => ErrorKind::DnsInternal,
            },
            ErrorRepr::DnsProtoError(ref e) => match e.kind() {
                DnsProtoErrorKind::Timeout => ErrorKind::DnsTimeout,
                _ => ErrorKind::DnsInternal,
            },
            ErrorRepr::HttpError(_) => ErrorKind::HttpInternal,
            ErrorRepr::SerializationError(_) => ErrorKind::OutputSerialization,
            ErrorRepr::WithMessageStr(kind, _) => kind,
            ErrorRepr::WithMessageString(kind, _) => kind,
        }
    }
}

impl fmt::Display for DonutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self.repr {
            ErrorRepr::Base64Error(ref e) => e.fmt(f),
            ErrorRepr::DnsClientError(ref e) => e.fmt(f),
            ErrorRepr::DnsParseError(ref e) => e.fmt(f),
            ErrorRepr::DnsProtoError(ref e) => e.fmt(f),
            ErrorRepr::HttpError(ref e) => e.fmt(f),
            ErrorRepr::SerializationError(ref e) => e.fmt(f),
            ErrorRepr::WithMessageStr(_, msg) => msg.fmt(f),
            ErrorRepr::WithMessageString(_, ref msg) => msg.fmt(f),
        }
    }
}

impl Fail for DonutError {
    fn cause(&self) -> Option<&dyn Fail> {
        match &self.repr {
            ErrorRepr::Base64Error(ref e) => e.cause(),
            ErrorRepr::DnsClientError(ref e) => e.cause(),
            ErrorRepr::DnsParseError(ref e) => e.cause(),
            ErrorRepr::DnsProtoError(ref e) => e.cause(),
            ErrorRepr::HttpError(ref e) => e.cause(),
            ErrorRepr::SerializationError(ref e) => e.cause(),
            _ => None,
        }
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        match &self.repr {
            ErrorRepr::Base64Error(ref e) => e.backtrace(),
            ErrorRepr::DnsClientError(ref e) => e.backtrace(),
            ErrorRepr::DnsParseError(ref e) => e.backtrace(),
            ErrorRepr::DnsProtoError(ref e) => e.backtrace(),
            ErrorRepr::HttpError(ref e) => e.backtrace(),
            ErrorRepr::SerializationError(ref e) => e.backtrace(),
            _ => None,
        }
    }
}

impl From<DecodeError> for DonutError {
    fn from(e: DecodeError) -> Self {
        DonutError {
            repr: ErrorRepr::Base64Error(e),
        }
    }
}

impl From<DnsClientError> for DonutError {
    fn from(e: DnsClientError) -> Self {
        DonutError {
            repr: ErrorRepr::DnsClientError(e),
        }
    }
}

impl From<DnsParseError> for DonutError {
    fn from(e: DnsParseError) -> Self {
        DonutError {
            repr: ErrorRepr::DnsParseError(e),
        }
    }
}

impl From<DnsProtoError> for DonutError {
    fn from(e: DnsProtoError) -> Self {
        DonutError {
            repr: ErrorRepr::DnsProtoError(e),
        }
    }
}

impl From<HyperError> for DonutError {
    fn from(e: HyperError) -> Self {
        DonutError {
            repr: ErrorRepr::HttpError(e),
        }
    }
}

impl From<SerdeError> for DonutError {
    fn from(e: SerdeError) -> Self {
        DonutError {
            repr: ErrorRepr::SerializationError(e),
        }
    }
}

impl From<(ErrorKind, &'static str)> for DonutError {
    fn from((kind, msg): (ErrorKind, &'static str)) -> Self {
        DonutError {
            repr: ErrorRepr::WithMessageStr(kind, msg),
        }
    }
}

impl From<(ErrorKind, String)> for DonutError {
    fn from((kind, msg): (ErrorKind, String)) -> Self {
        DonutError {
            repr: ErrorRepr::WithMessageString(kind, msg),
        }
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
