use crate::dns::{validate_kind, validate_name, UdpResolverBackend};
use crate::types::{DohRequest, DonutError, DonutResult};
use hyper::header::CONTENT_TYPE;
use hyper::{Body, Method, Request, Response, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;

const DEFAULT_CONTENT_TYPE: &str = "application/dns-json";

pub async fn http_route(req: Request<Body>, dns: Arc<UdpResolverBackend>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let params = match get_request_from_params(&req) {
                Ok(v) => v,
                Err(e) => {
                    eprint!("ERROR: {}", e);
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

fn get_request_from_params(req: &Request<Body>) -> DonutResult<DohRequest> {
    let qs = req.uri().query().unwrap_or("").to_string();
    let query = url::form_urlencoded::parse(qs.as_bytes());
    let params: HashMap<String, String> = query.into_owned().collect();

    let name = params
        .get("name")
        .ok_or_else(|| DonutError::InvalidInput)
        .and_then(|s| validate_name(s))?;
    let kind = params
        .get("type")
        .ok_or_else(|| DonutError::InvalidInput)
        .and_then(|s| validate_kind(s))?;
    let dnssec_data = params
        .get("do")
        .map(|s| (s == "1" || s.to_lowercase() == "true"))
        .unwrap_or(false);
    let checking_disabled = params
        .get("cd")
        .map(|s| (s == "1" || s.to_lowercase() == "true"))
        .unwrap_or(false);

    Ok(DohRequest::new(
        name,
        kind,
        checking_disabled,
        dnssec_data,
        DEFAULT_CONTENT_TYPE,
    ))
}

fn http_error_no_body(code: StatusCode) -> Response<Body> {
    Response::builder().status(code).body(Body::empty()).unwrap()
}
