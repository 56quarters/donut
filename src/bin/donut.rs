use clap::{crate_version, value_t, App, Arg, ArgMatches};
use donut::{http_route, DonutError, DonutResult, UdpResolverBackend};
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::process;
use std::sync::Arc;
use trust_dns::client::{Client, SyncClient};
use trust_dns::udp::UdpClientConnection;

const MAX_TERM_WIDTH: usize = 72;

fn parse_cli_opts<'a>(args: Vec<String>) -> ArgMatches<'a> {
    App::new("Donut DNS over HTTPS server")
        .version(crate_version!())
        .set_term_width(MAX_TERM_WIDTH)
        .about("\nBlah blah blah")
        .arg(
            Arg::with_name("upstream-udp")
                .long("upstream-udp")
                .default_value("127.0.0.1:53")
                .help("Send DNS queries to this upstream DNS server (via DNS over UDP).")
                .conflicts_with_all(&["upstream-tls", "upstream-https"]),
        )
        .arg(
            Arg::with_name("upstream-tls")
                .long("upstream-tls")
                .default_value("127.0.0.1:853")
                .help("Send DNS queries to this upstream DNS server (via DNS over TLS).")
                .conflicts_with_all(&["upstream-udp", "upstream-https"]),
        )
        .arg(
            Arg::with_name("upstream-https")
                .long("upstream-https")
                .default_value("127.0.0.1:443")
                .help("Send DNS queries to this upstream DNS server (via DNS over HTTPS).")
                .conflicts_with_all(&["upstream-udp", "upstream-tls"]),
        )
        .arg(
            Arg::with_name("bind")
                .long("bind")
                .default_value("127.0.0.1:3000")
                .help("Address to bind to."),
        )
        .get_matches_from(args)
}

fn to_socket_addr<A>(addr: A) -> DonutResult<SocketAddr>
where
    A: ToSocketAddrs,
{
    match addr.to_socket_addrs()?.next() {
        Some(addr) => Ok(addr),
        None => Err(DonutError::InvalidInputStr("socket address")),
    }
}

fn new_udp_resolver(addr: SocketAddr) -> UdpResolverBackend {
    let conn = UdpClientConnection::new(addr).unwrap();
    let client = SyncClient::new(conn);
    UdpResolverBackend::new(client)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    let matches = parse_cli_opts(args);

    let upstream = value_t!(matches, "upstream-udp", String)
        .map_err(|e| DonutError::from(e))
        .and_then(|a| to_socket_addr(a))
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            process::exit(1);
        });

    let resolver = Arc::new(new_udp_resolver(upstream.clone()));
    let service = make_service_fn(move |_| {
        let resolver = resolver.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| http_route(req, resolver.clone()))) }
    });

    let bind_addr = value_t!(matches, "bind", String)
        .map_err(|e| DonutError::from(e))
        .and_then(|a| to_socket_addr(a))
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            process::exit(1);
        });

    let server = Server::try_bind(&bind_addr)
        .unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            process::exit(1);
        });

    eprintln!("Using upstream DNS {}", upstream);
    eprintln!("Listening on http://{}", bind_addr);
    server.serve(service).await?;

    Ok(())
}
