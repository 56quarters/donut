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

use crate::request::{RequestParserJsonGet, RequestParserWireGet, RequestParserWirePost};
use crate::resolve::MultiTransportResolver;
use crate::response::{ResponseEncoderJson, ResponseEncoderWire, ResponseMetadata};
use crate::types::{DonutError, ErrorKind};
use futures_util::TryFutureExt;
use hyper::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE};
use hyper::{Body, Method, Request, Response, StatusCode};
use std::sync::Arc;
use tracing::{event, Level};

const WIRE_MESSAGE_FORMAT: &str = "application/dns-message";
const JSON_MESSAGE_FORMAT: &str = "application/dns-json";

#[derive(Debug)]
pub struct HandlerContext {
    json_parser: RequestParserJsonGet,
    get_parser: RequestParserWireGet,
    post_parser: RequestParserWirePost,
    resolver: MultiTransportResolver,
    json_encoder: ResponseEncoderJson,
    wire_encoder: ResponseEncoderWire,
}

impl HandlerContext {
    pub fn new(
        json_parser: RequestParserJsonGet,
        get_parser: RequestParserWireGet,
        post_parser: RequestParserWirePost,
        resolver: MultiTransportResolver,
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

pub async fn http_route(req: Request<Body>, context: Arc<HandlerContext>) -> Result<Response<Body>, hyper::Error> {
    // Copy all the request attributes we're matching on so that we can pass ownership
    // of the request into each parsing method (required for the POST parser since it
    // reads the body as a stream).
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let accept = req
        .headers()
        .get(ACCEPT)
        .and_then(|a| a.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let encoded = match (&method, path.as_ref(), accept.as_ref()) {
        (&Method::GET, "/dns-query", JSON_MESSAGE_FORMAT) => {
            context
                .json_parser
                .parse(req)
                .and_then(|r| context.resolver.resolve(r))
                .and_then(|r| context.json_encoder.encode(r))
                .await
        }
        (&Method::GET, "/dns-query", WIRE_MESSAGE_FORMAT) => {
            context
                .get_parser
                .parse(req)
                .and_then(|r| context.resolver.resolve(r))
                .and_then(|r| context.wire_encoder.encode(r))
                .await
        }
        (&Method::POST, "/dns-query", WIRE_MESSAGE_FORMAT) => {
            context
                .post_parser
                .parse(req)
                .and_then(|r| context.resolver.resolve(r))
                .and_then(|r| context.wire_encoder.encode(r))
                .await
        }

        // 400 for the correct path but an invalid Accept value
        (_, "/dns-query", _) => return Ok(http_status_no_body(StatusCode::BAD_REQUEST)),

        // 404 for everything else
        _ => return Ok(http_status_no_body(StatusCode::NOT_FOUND)),
    };

    Ok(encoded
        .map(|(meta, bytes)| render_ok(&method, &path, &accept, meta, bytes))
        .unwrap_or_else(|e| render_err(&method, &path, &accept, e)))
}

///
///
///
fn render_ok(method: &Method, path: &str, accept: &str, meta: ResponseMetadata, bytes: Vec<u8>) -> Response<Body> {
    event!(
        target: "donut_request",
        Level::INFO,
        method = %method,
        path = %path,
        accept = %accept,
        status = 200,
        bytes = bytes.len(),
    );

    let mut builder = Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, accept);
    if method == Method::GET {
        if let Some(ttl) = meta.min_ttl() {
            builder = builder.header(CACHE_CONTROL, format!("max-age={}", ttl));
        }
    }

    builder.body(Body::from(bytes)).unwrap()
}

///
///
///
fn render_err(method: &Method, path: &str, accept: &str, err: DonutError) -> Response<Body> {
    let status_code = match err.kind() {
        ErrorKind::InputParsing | ErrorKind::InputSerialization => StatusCode::BAD_REQUEST,
        ErrorKind::InputLengthBody => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorKind::InputLengthUri => StatusCode::URI_TOO_LONG,
        ErrorKind::DnsTimeout => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };

    event!(
        target: "donut_request",
        Level::WARN,
        method = %method,
        path = %path,
        accept = %accept,
        status = status_code.as_u16(),
        error_kind = ?err.kind(),
        error_msg = %err,
    );

    http_status_no_body(status_code)
}

///
///
///
fn http_status_no_body(code: StatusCode) -> Response<Body> {
    Response::builder().status(code).body(Body::empty()).unwrap()
}
