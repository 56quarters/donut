use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use donut::DohRequest;

async fn lookup(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let params = DohRequest::new("example.com:0".to_owned(), 1, false, "".to_owned(), true);
            let res = donut::lookup_from_system(&params);
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
