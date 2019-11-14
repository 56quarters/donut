use clap::{crate_version, value_t, App, Arg, ArgMatches};
use donut::http::{http_route, JsonHandlerContext};
use donut::request::RequestParserJsonGet;
use donut::resolve::UdpResolver;
use donut::response::ResponseEncoderJson;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::env;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use trust_dns::client::SyncClient;
use trust_dns::udp::UdpClientConnection;

const MAX_TERM_WIDTH: usize = 72;

// Set up the default upstream DNS server. We do this instead of using the
// `.default_value(...)` methods of clap because we need to mark the various
// types as conflicting with each other. This isn't possible when using default
// values. Instead, we create them in an easy to use form here (something that
// works with `SocketAddr::from()`).
const DEFAULT_UPSTREAM_UDP: ([u8; 4], u16) = ([127, 0, 0, 1], 53);

fn parse_cli_opts<'a>(args: Vec<String>) -> ArgMatches<'a> {
    App::new("Donut DNS over HTTPS server")
        .version(crate_version!())
        .set_term_width(MAX_TERM_WIDTH)
        .about("\nBlah blah blah")
        .arg(
            Arg::with_name("upstream-udp")
                .long("upstream-udp")
                .takes_value(true)
                .help("Send DNS queries to this upstream DNS server (via DNS over UDP)."),
        )
        .arg(
            Arg::with_name("bind")
                .long("bind")
                .default_value("127.0.0.1:3000")
                .help("Address to bind to."),
        )
        .get_matches_from(args)
}

fn new_handler_context(addr: SocketAddr) -> JsonHandlerContext {
    let conn = UdpClientConnection::new(addr).unwrap();
    let client = SyncClient::new(conn);

    let resolver = UdpResolver::new(client);
    let parser = RequestParserJsonGet::new();
    let encoder = ResponseEncoderJson::new();

    JsonHandlerContext::new(parser, resolver, encoder)
}

fn get_upstream(matches: &ArgMatches, param: &str) -> Option<Result<SocketAddr, clap::Error>> {
    match value_t!(matches, param, SocketAddr) {
        Err(e) if e.kind == clap::ErrorKind::ArgumentNotFound => None,
        Err(e) => Some(Err(e)),
        Ok(v) => Some(Ok(v)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    let matches = parse_cli_opts(args);

    let upstream = match get_upstream(&matches, "upstream-udp") {
        Some(Ok(v)) => v,
        Some(Err(e)) => e.exit(),
        None => SocketAddr::from(DEFAULT_UPSTREAM_UDP),
    };
    let context = Arc::new(new_handler_context(upstream.clone()));

    let service = make_service_fn(move |_| {
        let context = context.clone();
        async move { Ok::<_, hyper::Error>(service_fn(move |req| http_route(req, context.clone()))) }
    });

    let bind_addr = value_t!(matches, "bind", SocketAddr).unwrap_or_else(|e| e.exit());
    let server = Server::try_bind(&bind_addr).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        process::exit(1);
    });

    eprintln!("Using upstream DNS {}", upstream);
    eprintln!("Listening on http://{}", bind_addr);
    server.serve(service).await?;

    Ok(())
}
