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

use crate::types::{DonutError, DonutResult, ErrorKind};
use futures_util::{future, TryStreamExt};
use hyper::{Body, Request};
use std::collections::HashMap;
use tracing::{event, span, Instrument, Level};
use trust_dns_client::op::{MessageType, OpCode, Query};
use trust_dns_client::proto::op::Message;
use trust_dns_client::proto::serialize::binary::BinDecodable;
use trust_dns_client::proto::xfer::{DnsRequest, DnsRequestOptions};
use trust_dns_client::rr::{Name, RecordType};

/// Max size for a DNS message in bytes (POST body or GET parameter after decoding)
const MAX_MESSAGE_SIZE: usize = 512;

#[derive(Debug, Default, Clone)]
pub struct RequestParserJsonGet;

impl RequestParserJsonGet {
    pub fn new() -> Self {
        RequestParserJsonGet
    }

    pub async fn parse(&self, req: Request<Body>) -> DonutResult<DnsRequest> {
        let qs = req.uri().query().unwrap_or("").as_bytes();
        let query = url::form_urlencoded::parse(qs);
        let params: HashMap<String, String> = query.into_owned().collect();

        let name = params
            .get("name")
            .ok_or_else(|| DonutError::from((ErrorKind::InputInvalid, "missing query name")))
            .and_then(|s| Self::parse_query_name(s))?;
        let kind = params
            .get("type")
            .ok_or_else(|| DonutError::from((ErrorKind::InputInvalid, "missing query type")))
            .and_then(|s| Self::parse_query_type(s))?;
        let checking_disabled = params
            .get("cd")
            .map(|s| (s == "1" || s.to_lowercase() == "true"))
            .unwrap_or(false);

        let mut message = Message::default();
        message.add_query(Query::query(name, kind));
        message.set_checking_disabled(checking_disabled);
        message.set_recursion_desired(true);
        message = validate_message(message)?;

        event!(
            Level::TRACE,
            message = "parsed query params as DNS message",
            message_type = ?message.message_type(),
            query_count = message.queries().len(),
        );

        let meta = DnsRequestOptions {
            expects_multiple_responses: message.query_count() > 1,
            ..Default::default()
        };

        Ok(DnsRequest::new(message, meta))
    }

    fn parse_query_name(name: &str) -> DonutResult<Name> {
        name.parse()
            .map_err(|_| DonutError::from((ErrorKind::InputInvalid, "invalid query name")))
    }

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

        parsed_type.ok_or_else(|| DonutError::from((ErrorKind::InputInvalid, "invalid query type")))
    }
}

#[derive(Debug, Default, Clone)]
pub struct RequestParserWireGet;

impl RequestParserWireGet {
    pub fn new() -> Self {
        RequestParserWireGet
    }

    pub async fn parse(&self, req: Request<Body>) -> DonutResult<DnsRequest> {
        let qs = req.uri().query().unwrap_or("").as_bytes();
        let query = url::form_urlencoded::parse(qs);
        let params: HashMap<String, String> = query.into_owned().collect();

        let bytes = params
            .get("dns")
            .ok_or_else(|| DonutError::from((ErrorKind::InputInvalid, "missing 'dns' field")))
            .and_then(|d| {
                base64::decode_config(d, base64::URL_SAFE_NO_PAD)
                    .map_err(|e| DonutError::from((ErrorKind::InputInvalid, "invalid base64 value", Box::new(e))))
            })
            .and_then(|b| {
                // Ensure that size of the request (after base64 decoding) isn't longer
                // than the max DNS message size that we allow (512 bytes, which matches
                // the limit for POST requests).
                if b.len() > MAX_MESSAGE_SIZE {
                    Err(DonutError::from((ErrorKind::InputUriTooLong, "URI too long")))
                } else {
                    Ok(b)
                }
            })?;

        event!(Level::TRACE, message = "parsed base64 bytes", num_bytes = bytes.len());

        let message = Message::from_vec(&bytes)
            // Any errors while parsing a DNS Message get mapped to invalid input
            .map_err(|e| DonutError::from((ErrorKind::InputInvalid, "invalid DNS message", Box::new(e))))
            .map(|mut m| {
                m.set_recursion_desired(true);
                m
            })
            .and_then(validate_message)?;

        event!(
            Level::TRACE,
            message = "parsed bytes as DNS message",
            message_type = ?message.message_type(),
            query_count = message.queries().len(),
        );

        let meta = DnsRequestOptions {
            expects_multiple_responses: message.query_count() > 1,
            ..Default::default()
        };

        Ok(DnsRequest::new(message, meta))
    }
}

#[derive(Debug, Default, Clone)]
pub struct RequestParserWirePost;

impl RequestParserWirePost {
    pub fn new() -> Self {
        RequestParserWirePost
    }

    pub async fn parse(&self, req: Request<Body>) -> DonutResult<DnsRequest> {
        let bytes = Self::read_from_body(req.into_body(), MAX_MESSAGE_SIZE)
            .instrument(span!(Level::DEBUG, "read_from_body"))
            .await?;

        event!(Level::TRACE, message = "parsed body as bytes", num_bytes = bytes.len());

        let message = Message::from_bytes(&bytes)
            // Any errors while parsing a DNS Message get mapped to invalid input
            .map_err(|e| DonutError::from((ErrorKind::InputInvalid, "invalid DNS message", Box::new(e))))
            .map(|mut m| {
                m.set_recursion_desired(true);
                m
            })
            .and_then(validate_message)?;

        event!(
            Level::TRACE,
            message = "parsed bytes as DNS message",
            message_type = ?message.message_type(),
            query_count = message.queries().len(),
        );

        let meta = DnsRequestOptions {
            expects_multiple_responses: message.query_count() > 1,
            ..Default::default()
        };

        Ok(DnsRequest::new(message, meta))
    }

    async fn read_from_body(body: Body, n: usize) -> DonutResult<Vec<u8>> {
        body.map_err(|e| DonutError::from((ErrorKind::Internal, "cannot read HTTP body", Box::new(e))))
            .try_fold(Vec::new(), |mut acc, chunk| {
                if chunk.len() + acc.len() > n {
                    return future::err(DonutError::from((ErrorKind::InputBodyTooLong, "body too long")));
                }

                acc.extend_from_slice(&*chunk);
                future::ok(acc)
            })
            .await
    }
}

/// Perform extra semantic validation of DNS Messages
fn validate_message(message: Message) -> DonutResult<Message> {
    // We only parse incoming queries, reject anything else (updates, notifications, responses)
    if message.message_type() != MessageType::Query || message.op_code() != OpCode::Query {
        return Err(DonutError::from((
            ErrorKind::InputInvalid,
            "invalid message type or op code",
        )));
    }

    // NOTE: We use  the queries slice here instead of .query_count() since query counts
    // are only updated when message is "finalized" right before being sent to the server.
    // When we build the message piecemeal like for JSON requests, we don't have a "finalized"
    // message when validating it.
    if message.queries().is_empty() {
        return Err(DonutError::from((ErrorKind::InputInvalid, "no DNS queries in message")));
    }

    Ok(message)
}
