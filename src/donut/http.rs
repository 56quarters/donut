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

use crate::request::{RequestParserJsonGet, RequestParserWireGet};
use crate::resolve::UdpResolver;
use crate::response::{ResponseEncoderJson, ResponseEncoderWire};
use hyper::header::{HeaderValue, ACCEPT, CONTENT_TYPE};
use hyper::{Body, Method, Request, Response, StatusCode};
use std::sync::Arc;

const WIRE_MESSAGE_FORMAT: &str = "application/dns-message";
const JSON_MESSAGE_FORMAT: &str = "application/dns-json";

pub struct HandlerContext {
    json_parser: RequestParserJsonGet,
    get_parser: RequestParserWireGet,
    resolver: UdpResolver,
    json_encoder: ResponseEncoderJson,
    wire_encoder: ResponseEncoderWire,
}

impl HandlerContext {
    pub fn new(
        json_parser: RequestParserJsonGet,
        get_parser: RequestParserWireGet,
        resolver: UdpResolver,
        json_encoder: ResponseEncoderJson,
        wire_encoder: ResponseEncoderWire,
    ) -> Self {
        HandlerContext {
            json_parser,
            get_parser,
            resolver,
            json_encoder,
            wire_encoder,
        }
    }
}

pub async fn http_route(req: Request<Body>, context: Arc<HandlerContext>) -> Result<Response<Body>, hyper::Error> {
    // TODO: Match on Accept header to pick between wire / json format
    // TODO: Less copy/paste
    // TODO: tool to read from stdin and parse DNS response as text
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/dns-json") => {
            let params = match context.json_parser.parse(&req) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {:?}", e);
                    return Ok(http_error_no_body(StatusCode::BAD_REQUEST));
                }
            };

            eprintln!("PARAMS: {:?}", params);

            let result = match context.resolver.resolve(&params).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {:?}", e);
                    return Ok(http_error_no_body(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            eprintln!("RESULT: {:?}", result);

            let body = match context.json_encoder.encode(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {:?}", e);
                    return Ok(http_error_no_body(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, JSON_MESSAGE_FORMAT)
                .body(Body::from(body))
                .unwrap();

            Ok(response)
        }

        (&Method::GET, "/dns-query") => {
            let params = match context.get_parser.parse(&req) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {:?}", e);
                    return Ok(http_error_no_body(StatusCode::BAD_REQUEST));
                }
            };

            eprintln!("PARAMS: {:?}", params);

            let result = match context.resolver.resolve(&params).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {:?}", e);
                    return Ok(http_error_no_body(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            eprintln!("RESULT: {:?}", result);

            let body = match context.wire_encoder.encode(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {:?}", e);
                    return Ok(http_error_no_body(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, WIRE_MESSAGE_FORMAT)
                .body(Body::from(body))
                .unwrap();

            Ok(response)
        }

        (&Method::POST, _) => Ok(http_error_no_body(StatusCode::METHOD_NOT_ALLOWED)),

        _ => Ok(http_error_no_body(StatusCode::NOT_FOUND)),
    }
}

fn http_error_no_body(code: StatusCode) -> Response<Body> {
    Response::builder().status(code).body(Body::empty()).unwrap()
}
