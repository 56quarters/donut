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
use crate::response::{ResponseEncoderJson, ResponseEncoderWire};
use crate::types::ErrorKind;
use futures_util::TryFutureExt;
use hyper::header::{ACCEPT, CONTENT_TYPE};
use hyper::{Body, Method, Request, Response, StatusCode};
use std::sync::Arc;
use tracing::{event, Level};

const WIRE_MESSAGE_FORMAT: &str = "application/dns-message";
const JSON_MESSAGE_FORMAT: &str = "application/dns-json";

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

    let bytes = match (&method, path.as_ref(), accept.as_ref()) {
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
        (_, "/dns-query", _) => return Ok(http_error_no_body(StatusCode::BAD_REQUEST)),

        // 404 for everything else
        _ => return Ok(http_error_no_body(StatusCode::NOT_FOUND)),
    };

    Ok(bytes
        .map(|b| {
            event!(
                target: "donut_request",
                Level::INFO,
                method = %method,
                path = %path,
                accept = %accept,
                bytes = b.len(),
                status = 200,
            );

            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, &accept)
                .body(Body::from(b))
                .unwrap()
        })
        .unwrap_or_else(|e| {
            eprintln!("error: {:?} => {}", e.kind(), e);
            let status_code = match e.kind() {
                ErrorKind::InputParsing | ErrorKind::InputSerialization => StatusCode::BAD_REQUEST,
                ErrorKind::InputLength => StatusCode::PAYLOAD_TOO_LARGE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };

            http_error_no_body(status_code)
        }))
}

fn http_error_no_body(code: StatusCode) -> Response<Body> {
    Response::builder().status(code).body(Body::empty()).unwrap()
}
