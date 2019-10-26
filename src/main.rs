use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::Serialize;

struct DohRequest {
    name: String,
    kind: u32,
    checking_disabled: bool,
    content_type: String,
    dnssec_ok: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
struct DohQuestion {
    #[serde(rename = "name")]
    name: String,

    #[serde(rename = "type")]
    kind: u32,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
struct DohAnswer {
    #[serde(rename = "name")]
    name: String,

    #[serde(rename = "type")]
    kind: u32,

    #[serde(rename = "TTL")]
    ttl: u32,

    #[serde(rename = "data")]
    data: String,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
struct DohResult {
    #[serde(rename = "Status")]
    status: u32,

    #[serde(rename = "TC")]
    truncated: bool,

    #[serde(rename = "RD")]
    recursive_desired: bool,

    #[serde(rename = "RA")]
    recursion_available: bool,

    #[serde(rename = "AD")]
    all_validated: bool,

    #[serde(rename = "CD")]
    checking_disabled: bool,

    #[serde(rename = "Question")]
    questions: Vec<DohQuestion>,

    #[serde(rename = "Answer")]
    answers: Vec<DohAnswer>,
}

async fn lookup(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::GET, "/") => {
            let res = DohResult::default();
            let body = serde_json::to_vec(&res).unwrap();

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap();

            Ok(response)
        }

        (&Method::POST, _) => {
            let mut not_allowed = Response::default();
            *not_allowed.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            Ok(not_allowed)
        }

        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = ([127, 0, 0, 1], 3000).into();
    let service = make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(lookup)) });
    let server = Server::bind(&addr).serve(service);

    println!("Listening on http://{}", addr);
    server.await?;

    Ok(())
}
