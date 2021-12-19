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

use std::error::Error;
use std::fmt;
use trust_dns_client::proto::error::{ProtoError as DnsProtoError, ProtoErrorKind as DnsProtoErrorKind};

pub type DonutResult<T> = Result<T, DonutError>;

#[derive(Debug)]
enum ErrorRepr {
    DnsProtoError(DnsProtoError),
    KindMsg(ErrorKind, &'static str),
    KindMsgCause(ErrorKind, &'static str, Box<dyn Error + Send + Sync>),
}

#[derive(PartialEq, Eq, Debug, Hash, Clone, Copy)]
pub enum ErrorKind {
    Internal,
    Timeout,
    InputInvalid,
    InputBodyTooLong,
    InputUriTooLong,
}

#[derive(Debug)]
pub struct DonutError {
    repr: ErrorRepr,
}

impl DonutError {
    pub fn kind(&self) -> ErrorKind {
        match self.repr {
            ErrorRepr::DnsProtoError(ref e) => match e.kind() {
                DnsProtoErrorKind::Timeout => ErrorKind::Timeout,
                _ => ErrorKind::Internal,
            },
            ErrorRepr::KindMsg(kind, _) => kind,
            ErrorRepr::KindMsgCause(kind, _, _) => kind,
        }
    }
}

impl fmt::Display for DonutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self.repr {
            ErrorRepr::DnsProtoError(ref e) => write!(f, "DNS error: {}", e),
            ErrorRepr::KindMsg(_, msg) => msg.fmt(f),
            ErrorRepr::KindMsgCause(_, msg, ref e) => write!(f, "{}: {}", msg, e),
        }
    }
}

impl Error for DonutError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.repr {
            ErrorRepr::DnsProtoError(ref e) => Some(e),
            ErrorRepr::KindMsgCause(_, _, ref e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

// Dedicated `From` implementation for DNS related errors since they can be
// related to timeouts talking to upstream servers or other reasons. We need
// to be able differentiate between these cases so centralizing that logic
// here is the best way to do that.
impl From<DnsProtoError> for DonutError {
    fn from(e: DnsProtoError) -> Self {
        DonutError {
            repr: ErrorRepr::DnsProtoError(e),
        }
    }
}

impl From<(ErrorKind, &'static str)> for DonutError {
    fn from((kind, msg): (ErrorKind, &'static str)) -> Self {
        DonutError {
            repr: ErrorRepr::KindMsg(kind, msg),
        }
    }
}

impl<E> From<(ErrorKind, &'static str, E)> for DonutError
where
    E: Error + Send + Sync + 'static,
{
    fn from((kind, msg, e): (ErrorKind, &'static str, E)) -> Self {
        DonutError {
            repr: ErrorRepr::KindMsgCause(kind, msg, Box::new(e)),
        }
    }
}
