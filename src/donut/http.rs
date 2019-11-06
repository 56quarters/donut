use crate::dns::UdpResolverBackend;
use crate::types::{DohRequest, DonutError, DonutResult};
use hyper::header::CONTENT_TYPE;
use hyper::{Body, Method, Request, Response, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use trust_dns::rr::{Name, RecordType};

const DEFAULT_CONTENT_TYPE: &str = "application/dns-json";

pub async fn http_route(req: Request<Body>, dns: Arc<UdpResolverBackend>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let params = match get_request_from_params(&req) {
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

fn get_request_from_params(req: &Request<Body>) -> DonutResult<DohRequest> {
    let qs = req.uri().query().unwrap_or("").to_string();
    let query = url::form_urlencoded::parse(qs.as_bytes());
    let params: HashMap<String, String> = query.into_owned().collect();

    let name = params
        .get("name")
        .ok_or_else(|| DonutError::InvalidInputStr("name"))
        .and_then(|s| parse_query_name(s))?;
    let kind = params
        .get("type")
        .ok_or_else(|| DonutError::InvalidInputStr("type"))
        .and_then(|s| parse_requery_type(s))?;
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

///
///
///
fn parse_query_name(name: &str) -> DonutResult<Name> {
    name.parse().map_err(|_| DonutError::InvalidInputStr("name"))
}

///
///
///
fn parse_requery_type(kind: &str) -> DonutResult<RecordType> {
    let parsed_type: Option<RecordType> = kind
        // Attempt to parse the input string as a number (1..65535)
        .parse::<u16>()
        .ok()
        .map(|i| RecordType::from(i))
        .and_then(|r| match r {
            // Filter out the "unknown" variant that parsing yields
            RecordType::Unknown(_) => None,
            _ => Some(r),
        })
        // If it wasn't a number, try to parse it as a string (A, AAAA, etc).
        .or_else(|| kind.to_uppercase().parse().ok());

    parsed_type.ok_or_else(|| DonutError::InvalidInputStr("type"))
}

fn http_error_no_body(code: StatusCode) -> Response<Body> {
    Response::builder().status(code).body(Body::empty()).unwrap()
}
