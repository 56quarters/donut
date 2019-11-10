use crate::dns::UdpResolverBackend;
use crate::request::RequestParserJsonGet;
use hyper::header::CONTENT_TYPE;
use hyper::{Body, Method, Request, Response, StatusCode};
use std::sync::Arc;

const WIRE_MESSAGE_FORMAT: &str = "application/dns-message";
const JSON_MESSAGE_FORMAT: &str = "application/dns-json";

pub async fn http_route(req: Request<Body>, dns: Arc<UdpResolverBackend>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let parser = RequestParserJsonGet::new();
            let params = match parser.parse(&req) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {}", e);
                    return Ok(http_error_no_body(StatusCode::BAD_REQUEST));
                }
            };

            let result = match dns.resolve(&params).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {}", e);
                    return Ok(http_error_no_body(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            let body = match serde_json::to_vec(&result) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {}", e);
                    return Ok(http_error_no_body(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
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
