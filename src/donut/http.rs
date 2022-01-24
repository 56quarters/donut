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

use crate::request::{RequestParserJsonGet, RequestParserWireGet, RequestParserWirePost};
use crate::resolve::UdpResolver;
use crate::response::{ResponseEncoderJson, ResponseEncoderWire, ResponseMetadata};
use crate::types::{DonutError, ErrorKind};
use bytes::Bytes;
use futures_util::TryFutureExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{span, Instrument, Level};
use warp::http::header::ACCEPT;
use warp::http::HeaderValue;
use warp::http::StatusCode;
use warp::{Filter, Rejection, Reply};

const WIRE_MESSAGE_FORMAT: &str = "application/dns-message";
const JSON_MESSAGE_FORMAT: &str = "application/dns-json";

#[derive(Debug)]
pub struct HandlerContext {
    json_parser: RequestParserJsonGet,
    get_parser: RequestParserWireGet,
    post_parser: RequestParserWirePost,
    resolver: UdpResolver,
    json_encoder: ResponseEncoderJson,
    wire_encoder: ResponseEncoderWire,
}

impl HandlerContext {
    pub fn new(
        json_parser: RequestParserJsonGet,
        get_parser: RequestParserWireGet,
        post_parser: RequestParserWirePost,
        resolver: UdpResolver,
        json_encoder: ResponseEncoderJson,
        wire_encoder: ResponseEncoderWire,
    ) -> Self {
        HandlerContext {
            json_parser,
            get_parser,
            post_parser,
            resolver,
            json_encoder,
            wire_encoder,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonQuery {
    #[serde(alias = "name")]
    name: String,
    #[serde(alias = "type")]
    kind: String,
    #[serde(alias = "cd")]
    checking_disabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WireGetQuery {
    #[serde(alias = "dns")]
    dns: String,
}

#[derive(Debug)]
struct DnsResponseReply {
    result: Result<(ResponseMetadata, Vec<u8>), DonutError>,
    content_type: &'static str,
}

impl DnsResponseReply {
    fn new(result: Result<(ResponseMetadata, Vec<u8>), DonutError>, content_type: &'static str) -> Self {
        DnsResponseReply { result, content_type }
    }

    fn success(content_type: &'static str, meta: ResponseMetadata, bytes: Vec<u8>) -> warp::reply::Response {
        let mut res = warp::http::Response::new(bytes.into());
        let headers = res.headers_mut();

        headers.insert(warp::http::header::CONTENT_TYPE, HeaderValue::from_static(content_type));

        if let Some(ttl) = meta.min_ttl() {
            let caching = HeaderValue::from_maybe_shared(format!("max-age={}", ttl)).unwrap();
            headers.insert(warp::http::header::CACHE_CONTROL, caching);
        }

        res
    }

    fn error(content_type: &'static str, err: DonutError) -> warp::reply::Response {
        let status_code = match err.kind() {
            ErrorKind::InputInvalid => StatusCode::BAD_REQUEST,
            ErrorKind::InputBodyTooLong => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorKind::InputUriTooLong => StatusCode::URI_TOO_LONG,
            ErrorKind::Timeout => StatusCode::SERVICE_UNAVAILABLE,
            ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };

        tracing::error!(
            accept = %content_type,
            status = status_code.as_u16(),
            error_kind = ?err.kind(),
            error_msg = %err,
        );

        status_code.into_response()
    }
}

impl Reply for DnsResponseReply {
    fn into_response(self) -> warp::reply::Response {
        match self.result {
            Ok((meta, bytes)) => Self::success(self.content_type, meta, bytes),
            Err(e) => Self::error(self.content_type, e),
        }
    }
}

pub fn json_get(context: Arc<HandlerContext>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path("dns-query")
        .and(warp::filters::method::get())
        .and(warp::header::exact_ignore_case(ACCEPT.as_str(), JSON_MESSAGE_FORMAT))
        .and(warp::query::query::<JsonQuery>())
        .and_then(move |q: JsonQuery| {
            let context = context.clone();
            async move {
                let r = context
                    .json_parser
                    .parse(q.name, q.kind, q.checking_disabled.unwrap_or(false))
                    .instrument(span!(Level::DEBUG, "donut_parser_json"))
                    .and_then(|r| context.resolver.resolve(r))
                    .instrument(span!(Level::DEBUG, "donut_resolver_udp"))
                    .and_then(|r| context.json_encoder.encode(r))
                    .instrument(span!(Level::DEBUG, "donut_encoder_json"))
                    .await;

                Ok::<DnsResponseReply, Rejection>(DnsResponseReply::new(r, JSON_MESSAGE_FORMAT))
            }
        })
}

pub fn wire_get(context: Arc<HandlerContext>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path("dns-query")
        .and(warp::filters::method::get())
        .and(warp::header::exact_ignore_case(ACCEPT.as_str(), WIRE_MESSAGE_FORMAT))
        .and(warp::query::query::<WireGetQuery>())
        .and_then(move |q: WireGetQuery| {
            let context = context.clone();
            async move {
                let r = context
                    .get_parser
                    .parse(q.dns)
                    .instrument(span!(Level::DEBUG, "donut_parser_get"))
                    .and_then(|r| context.resolver.resolve(r))
                    .instrument(span!(Level::DEBUG, "donut_resolver_udp"))
                    .and_then(|r| context.wire_encoder.encode(r))
                    .instrument(span!(Level::DEBUG, "donut_encoder_wire"))
                    .await;

                Ok::<DnsResponseReply, Rejection>(DnsResponseReply::new(r, WIRE_MESSAGE_FORMAT))
            }
        })
}

pub fn wire_post(context: Arc<HandlerContext>) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path("dns-query")
        .and(warp::filters::method::post())
        .and(warp::header::exact_ignore_case(ACCEPT.as_str(), WIRE_MESSAGE_FORMAT))
        .and(warp::body::content_length_limit(crate::MAX_MESSAGE_SIZE as u64))
        .and(warp::filters::body::bytes())
        .and_then(move |body: Bytes| {
            let context = context.clone();
            async move {
                let r = context
                    .post_parser
                    .parse(body)
                    .instrument(span!(Level::DEBUG, "donut_parser_post"))
                    .and_then(|r| context.resolver.resolve(r))
                    .instrument(span!(Level::DEBUG, "donut_resolver_udp"))
                    .and_then(|r| context.wire_encoder.encode(r))
                    .instrument(span!(Level::DEBUG, "donut_encoder_wire"))
                    .await;

                Ok::<DnsResponseReply, Rejection>(DnsResponseReply::new(r, WIRE_MESSAGE_FORMAT))
            }
        })
}
