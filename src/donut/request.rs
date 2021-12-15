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

use crate::types::{DohRequest, DonutError, DonutResult, ErrorKind};
use futures_util::{future, TryStreamExt};
use hyper::{Body, Request};
use std::collections::HashMap;
use trust_dns_client::proto::op::Message;
use trust_dns_client::proto::serialize::binary::BinDecodable;
use trust_dns_client::rr::{Name, RecordType};

/// Max size for a DNS message in bytes (POST body or GET parameter after decoding)
const MAX_MESSAGE_SIZE: usize = 512;

///
///
///
#[derive(Debug, Default, Clone)]
pub struct RequestParserJsonGet;

impl RequestParserJsonGet {
    pub fn new() -> Self {
        RequestParserJsonGet
    }

    ///
    ///
    ///
    pub async fn parse(&self, req: Request<Body>) -> DonutResult<DohRequest> {
        let qs = req.uri().query().unwrap_or("").as_bytes();
        let query = url::form_urlencoded::parse(qs);
        let params: HashMap<String, String> = query.into_owned().collect();

        let name = params
            .get("name")
            .ok_or_else(|| DonutError::from((ErrorKind::InputParsing, "missing query name")))
            .and_then(|s| Self::parse_query_name(s))?;
        let kind = params
            .get("type")
            .ok_or_else(|| DonutError::from((ErrorKind::InputParsing, "missing query type")))
            .and_then(|s| Self::parse_query_type(s))?;
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
        name.parse()
            .map_err(|_| DonutError::from((ErrorKind::InputParsing, "invalid query name")))
    }

    ///
    ///
    ///
    fn parse_query_type(kind: &str) -> DonutResult<RecordType> {
        let parsed_type: Option<RecordType> = kind
            // Attempt to parse the input string as a number (1..65535)
            .parse::<u16>()
            .ok()
            .map(RecordType::from)
            .and_then(|r| match r {
                // Filter out the "unknown" variant that parsing yields
                RecordType::Unknown(_) => None,
                _ => Some(r),
            })
            // If it wasn't a number, try to parse it as a string (A, AAAA, etc).
            .or_else(|| kind.to_uppercase().parse().ok());

        parsed_type.ok_or_else(|| DonutError::from((ErrorKind::InputParsing, "invalid query type")))
    }
}

///
///
///
#[derive(Debug, Default, Clone)]
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
    pub async fn parse(&self, req: Request<Body>) -> DonutResult<DohRequest> {
        let qs = req.uri().query().unwrap_or("").as_bytes();
        let query = url::form_urlencoded::parse(qs);
        let params: HashMap<String, String> = query.into_owned().collect();

        let message = params
            .get("dns")
            .ok_or_else(|| DonutError::from((ErrorKind::InputParsing, "missing dns field")))
            .and_then(|d| base64::decode_config(d, base64::URL_SAFE_NO_PAD).map_err(DonutError::from))
            .and_then(|b| {
                // Ensure that size of the request (after base64 decoding) isn't longer
                // than the max DNS message size that we allow (512 bytes, which matches
                // the limit for POST requests).
                if b.len() > MAX_MESSAGE_SIZE {
                    Err(DonutError::from((ErrorKind::InputLengthUri, "uri too long")))
                } else {
                    Ok(b)
                }
            })
            .and_then(|b| Message::from_vec(&b).map_err(DonutError::from))?;

        let (name, kind) = question_from_message(&message)?;
        Ok(DohRequest::new(name, kind, message.checking_disabled(), false))
    }
}

///
///
///
#[derive(Debug, Clone)]
pub struct RequestParserWirePost {
    max_size: usize,
}

impl RequestParserWirePost {
    /// Create a new POST request parers with the provided max body size limit.
    ///
    /// If the limit is larger than 512 bytes, 512 bytes will be used as the max.
    pub fn new(max_size: usize) -> Self {
        RequestParserWirePost {
            max_size: MAX_MESSAGE_SIZE.min(max_size),
        }
    }

    ///
    ///
    ///
    pub async fn parse(&self, req: Request<Body>) -> DonutResult<DohRequest> {
        let bytes = Self::read_from_body(req.into_body(), self.max_size).await?;
        let message = Message::from_bytes(&bytes).map_err(DonutError::from)?;
        let (name, kind) = question_from_message(&message)?;
        Ok(DohRequest::new(name, kind, message.checking_disabled(), false))
    }

    /// Asynchronously read `n` bytes from the given body, consuming it.
    ///
    /// # Errors
    ///
    /// Return an error if the body is longer than `n` bytes.
    async fn read_from_body(body: Body, n: usize) -> DonutResult<Vec<u8>> {
        body.map_err(DonutError::from)
            .try_fold(Vec::new(), |mut acc, chunk| {
                if chunk.len() + acc.len() > n {
                    return future::err(DonutError::from((ErrorKind::InputLengthBody, "body too long")));
                }

                acc.extend_from_slice(&*chunk);
                future::ok(acc)
            })
            .await
    }
}

impl Default for RequestParserWirePost {
    fn default() -> Self {
        Self::new(MAX_MESSAGE_SIZE)
    }
}

/// Get the first `Name` and `RecordType` from a given message question without consuming it
///
/// # Errors
///
/// Return an error if there is no question included in the message.
fn question_from_message(message: &Message) -> DonutResult<(Name, RecordType)> {
    message
        .queries()
        .first()
        .map(|q| (q.name().clone(), q.query_type()))
        .ok_or_else(|| DonutError::from((ErrorKind::InputParsing, "missing question")))
}
