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

use crate::types::{DohRequest, DonutError, DonutResult};
use hyper::{Body, Request};
use std::collections::HashMap;
use trust_dns::proto::op::Message;
use trust_dns::proto::serialize::binary::BinDecodable;
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
            .ok_or_else(|| DonutError::InvalidInputStr("missing query name"))
            .and_then(|s| Self::parse_query_name(s))?;
        let kind = params
            .get("type")
            .ok_or_else(|| DonutError::InvalidInputStr("missing query type"))
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
        name.parse()
            .map_err(|_| DonutError::InvalidInputStr("invalid query name"))
    }

    ///
    ///
    ///
    fn parse_requery_type(kind: &str) -> DonutResult<RecordType> {
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

        parsed_type.ok_or_else(|| DonutError::InvalidInputStr("invalid query type"))
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

        let message = params
            .get("dns")
            .ok_or_else(|| DonutError::InvalidInputStr("missing dns field"))
            .and_then(|d| base64::decode_config(d, base64::URL_SAFE_NO_PAD).map_err(DonutError::from))
            .and_then(|b| Message::from_bytes(&b).map_err(DonutError::from))?;

        let (name, kind) = message
            .queries()
            .first()
            .map(|q| (q.name().clone(), q.query_type()))
            .ok_or_else(|| DonutError::InvalidInputStr("missing question"))?;

        Ok(DohRequest::new(name, kind, message.checking_disabled(), false))
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
