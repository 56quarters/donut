use crate::request::{RequestParserJsonGet, RequestParserWireGet};
use crate::resolve::UdpResolver;
use crate::response::{ResponseEncoderJson, ResponseEncoderWire};
use hyper::header::{CONTENT_TYPE, ACCEPT, HeaderValue};
use hyper::{Body, Method, Request, Response, StatusCode};
use std::sync::Arc;

const WIRE_MESSAGE_FORMAT: &str = "application/dns-message";
const JSON_MESSAGE_FORMAT: &str = "application/dns-json";

pub struct WireGetHandlerContext {
    parser: RequestParserWireGet,
    resolver: UdpResolver,
    encoder: ResponseEncoderWire,
}

pub struct JsonHandlerContext {
    parser: RequestParserJsonGet,
    resolver: UdpResolver,
    encoder: ResponseEncoderJson,
}

impl JsonHandlerContext {
    pub fn new(parser: RequestParserJsonGet, resolver: UdpResolver, encoder: ResponseEncoderJson) -> Self {
        JsonHandlerContext {
            parser,
            resolver,
            encoder,
        }
    }
}

pub async fn http_route(req: Request<Body>, context: Arc<JsonHandlerContext>) -> Result<Response<Body>, hyper::Error> {
    // TODO: Match on Accept header to pick between wire / json format
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/dns-query") => {
            let params = match context.parser.parse(&req) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {}", e);
                    return Ok(http_error_no_body(StatusCode::BAD_REQUEST));
                }
            };

            let result = match context.resolver.resolve(&params).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {}", e);
                    return Ok(http_error_no_body(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            let body = match context.encoder.encode(&params, &result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {}", e);
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

        (&Method::POST, _) => Ok(http_error_no_body(StatusCode::METHOD_NOT_ALLOWED)),

        _ => Ok(http_error_no_body(StatusCode::NOT_FOUND)),
    }
}

fn is_json_get(req: &Request<Body>) -> bool {
    unimplemented!();
}

fn is_wire_get(req: &Request<Body>) -> bool {
    unimplemented!();
}

fn is_wire_post(req: &Request<Body>) -> bool {
    unimplemented!();
}

fn http_error_no_body(code: StatusCode) -> Response<Body> {
    Response::builder().status(code).body(Body::empty()).unwrap()
}
