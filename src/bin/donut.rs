use donut::{DohRequest, UdpResolverBackend};
use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use trust_dns::client::SyncClient;
use trust_dns::udp::UdpClientConnection;

fn new_udp_resolver(addr: &str) -> UdpResolverBackend {
    let address = addr.parse().unwrap();
    let conn = UdpClientConnection::new(address).unwrap();
    let client = SyncClient::new(conn);
    UdpResolverBackend::new(client)
}

async fn lookup(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let params = DohRequest::new("56quarters.xyz", 28, false, "".to_owned(), true);
            let resolver = new_udp_resolver("127.0.0.1:53");

            let res = match resolver.resolve(&params).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {}", e);
                    return Ok(http_error_response(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            let body = match serde_json::to_vec(&res) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("ERROR: {}", e);
                    return Ok(http_error_response(StatusCode::INTERNAL_SERVER_ERROR));
                }
            };

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap();

            Ok(response)
        }

        (&Method::POST, _) => Ok(http_error_response(StatusCode::METHOD_NOT_ALLOWED)),

        _ => Ok(http_error_response(StatusCode::NOT_FOUND)),
    }
}

fn http_error_response(code: StatusCode) -> Response<Body> {
    return Response::builder()
        .status(code)
        .body(Body::empty())
        .unwrap();
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
