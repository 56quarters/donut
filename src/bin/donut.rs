// Donut - DNS over HTTPS server
//
// Copyright 2019 Nick Pillitteri
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

use clap::{crate_version, value_t, App, Arg, ArgMatches};
use donut::http::{http_route, HandlerContext};
use donut::request::{RequestParserJsonGet, RequestParserWireGet, RequestParserWirePost};
use donut::resolve::UdpResolver;
use donut::response::{ResponseEncoderJson, ResponseEncoderWire};
use donut::types::DonutResult;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;
use std::env;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{event, span, Instrument, Level};
use trust_dns_client::client::AsyncClient;
use trust_dns_client::udp::UdpClientStream;

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
        .about("\nHTTP server for DNS-over-HTTPS lookups (binary and JSON)")
        .arg(
            Arg::with_name("upstream-udp")
                .long("upstream-udp")
                .takes_value(true)
                .help("Send DNS queries to this upstream DNS server (via DNS over UDP)."),
        )
        .arg(
            Arg::with_name("upstream-timeout")
                .long("upstream-timeout")
                .default_value("1000")
                .help("Timeout for upstream DNS server in milliseconds."),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .default_value("info")
                .help(concat!(
                    "Logging verbosity. Allowed values are 'trace', 'debug', 'info', 'warn', ",
                    "and 'error' -- in decreasing order of verbosity"
                )),
        )
        .arg(
            Arg::with_name("bind")
                .long("bind")
                .default_value("127.0.0.1:3000")
                .help("Address to bind to."),
        )
        .get_matches_from(args)
}

async fn new_udp_dns_client(addr: SocketAddr, timeout: Duration) -> DonutResult<AsyncClient> {
    let conn = UdpClientStream::<UdpSocket>::with_timeout(addr, timeout);
    let (client, bg) = AsyncClient::connect(conn).await?;
    // Trust DNS clients are really just handles for talking to a future running in the background
    // that actually does all the network activity and DNS lookups. Start the background future here
    // on whatever Tokio executor has been set up when `main()` was run.
    tokio::spawn(bg);
    Ok(client)
}

async fn new_handler_context(addr: SocketAddr, timeout: Duration) -> DonutResult<HandlerContext> {
    let client = new_udp_dns_client(addr, timeout).await?;
    let resolver = UdpResolver::new(client);
    let json_parser = RequestParserJsonGet::default();
    let get_parser = RequestParserWireGet::default();
    let post_parser = RequestParserWirePost::default();
    let json_encoder = ResponseEncoderJson::default();
    let wire_encoder = ResponseEncoderWire::default();

    Ok(HandlerContext::new(
        json_parser,
        get_parser,
        post_parser,
        resolver,
        json_encoder,
        wire_encoder,
    ))
}

fn get_upstream(matches: &ArgMatches<'_>, param: &str) -> Option<Result<SocketAddr, clap::Error>> {
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

    let log_level = value_t!(matches, "log-level", Level).unwrap_or_else(|e| e.exit());
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(log_level)
            .finish(),
    )
    .expect("Failed to set tracing subscriber");

    let upstream = match get_upstream(&matches, "upstream-udp") {
        Some(Ok(v)) => v,
        Some(Err(e)) => e.exit(),
        None => SocketAddr::from(DEFAULT_UPSTREAM_UDP),
    };

    let timeout = value_t!(matches, "upstream-timeout", u64)
        .map(Duration::from_millis)
        .unwrap_or_else(|e| e.exit());

    let context = Arc::new(new_handler_context(upstream, timeout).await.unwrap());
    let service = make_service_fn(move |_| {
        let context = context.clone();

        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                http_route(req, context.clone()).instrument(span!(Level::DEBUG, "donut::request"))
            }))
        }
    });

    let bind_addr = value_t!(matches, "bind", SocketAddr).unwrap_or_else(|e| e.exit());
    let server = Server::try_bind(&bind_addr).unwrap_or_else(|e| {
        event!(
            target: "donut_server",
            Level::ERROR,
            message = "server failed to start",
            error = %e,
        );

        process::exit(1);
    });

    event!(
        target: "donut_server",
        Level::INFO,
        message = "server started",
        upstream = %upstream,
        address = %bind_addr,
        timeout_ms = %timeout.as_millis(),
    );

    server.serve(service).await?;

    Ok(())
}
