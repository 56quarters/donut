use donut::DohRequest;
use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::Serialize;

async fn lookup(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let params = DohRequest::new("example.com", 1, false, "".to_owned(), true);
            let res = donut::lookup_from_system(&params);
            let body = serde_json::to_vec(&res).unwrap();
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap();

            Ok(response)
        }

        (&Method::POST, _) => http_error_response(StatusCode::METHOD_NOT_ALLOWED),

        _ => http_error_response(StatusCode::NOT_FOUND),
    }
}

fn http_error_response(code: StatusCode) -> Result<Response<Body>, hyper::Error> {
    let response = Response::builder()
        .status(code)
        .body(Body::empty())
        .unwrap();
    Ok(response)
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
