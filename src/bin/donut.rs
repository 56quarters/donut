use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use trust_dns::client::SyncClient;
use trust_dns::udp::UdpClientConnection;

use donut::{http_route, UdpResolverBackend};

fn new_udp_resolver(addr: &str) -> UdpResolverBackend {
    let address = addr.parse().unwrap();
    let conn = UdpClientConnection::new(address).unwrap();
    let client = SyncClient::new(conn);
    UdpResolverBackend::new(client)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = "127.0.0.1:3000".parse().unwrap();
    let resolver = Arc::new(new_udp_resolver("127.0.0.1:53"));

    let service = make_service_fn(move |_| {
        let resolver = resolver.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| http_route(req, resolver.clone()))) }
    });

    let server = Server::bind(&addr).serve(service);
    println!("Listening on http://{}", addr);
    server.await?;

    Ok(())
}
