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

use clap::Parser;
use donut::http::HandlerContext;
use donut::request::{RequestParserJsonGet, RequestParserWireGet, RequestParserWirePost};
use donut::resolve::UdpResolver;
use donut::response::{ResponseEncoderJson, ResponseEncoderWire};
use donut::types::DonutResult;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::signal::unix::{self, SignalKind};
use tracing::Level;
use trust_dns_client::client::AsyncClient;
use trust_dns_client::udp::UdpClientStream;
use warp::Filter;

const DEFAULT_UPSTREAM_UDP: ([u8; 4], u16) = ([127, 0, 0, 1], 53);
const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 1000;
const DEFAULT_LOG_LEVEL: Level = Level::INFO;
const DEFAULT_BIND_ADDR: ([u8; 4], u16) = ([127, 0, 0, 1], 3000);

/// Donut DNS over HTTPS server
///
/// HTTP server for DNS-over-HTTPS lookups (binary and JSON)
#[derive(Debug, Parser)]
#[clap(name = "donut", version = clap::crate_version!())]
struct DonutApplication {
    /// Send DNS queries to this upstream DNS server (via DNS over UDP)
    #[clap(long, default_value_t = DEFAULT_UPSTREAM_UDP.into())]
    upstream_udp: SocketAddr,

    /// Timeout for upstream DNS server in milliseconds.
    #[clap(long, default_value_t = DEFAULT_UPSTREAM_TIMEOUT_MS)]
    upstream_timeout: u64,

    /// Logging verbosity. Allowed values are 'trace', 'debug', 'info', 'warn', and 'error' (case insensitive).
    #[clap(long, default_value_t = DEFAULT_LOG_LEVEL)]
    log_level: Level,

    /// Address to bind to.
    #[clap(long, default_value_t = DEFAULT_BIND_ADDR.into())]
    bind: SocketAddr,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let opts = DonutApplication::parse();

    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(opts.log_level)
            .finish(),
    )
    .expect("Failed to set tracing subscriber");

    let timeout = Duration::from_millis(opts.upstream_timeout);
    let context = Arc::new(new_handler_context(opts.upstream_udp, timeout).await.unwrap());

    let handler = donut::http::json_get(context.clone())
        .or(donut::http::wire_get(context.clone()))
        .or(donut::http::wire_post(context.clone()))
        .or(donut::http::fallback());

    let (sock, server) = warp::serve(handler)
        .try_bind_with_graceful_shutdown(opts.bind, async {
            // Wait for either SIGTERM or SIGINT to shutdown
            tokio::select! {
                _ = sigterm() => {}
                _ = sigint() => {}
            }
        })
        .unwrap_or_else(|e| {
            tracing::error!(message = "error binding to address", address = %opts.bind, error = %e);
            process::exit(1)
        });

    tracing::info!(message = "server started", address = %sock);
    server.await;

    tracing::info!("server shutdown");
    Ok(())
}

/// Return after the first SIGTERM signal received by this process
async fn sigterm() -> io::Result<()> {
    unix::signal(SignalKind::terminate())?.recv().await;
    Ok(())
}

/// Return after the first SIGINT signal received by this process
async fn sigint() -> io::Result<()> {
    unix::signal(SignalKind::interrupt())?.recv().await;
    Ok(())
}
