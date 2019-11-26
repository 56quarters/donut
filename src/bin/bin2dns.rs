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

use clap::{crate_version, App, ArgMatches};
use std::env;
use tokio::prelude::*;
use trust_dns::op::Message;

const MAX_TERM_WIDTH: usize = 72;

fn parse_cli_opts<'a>(args: Vec<String>) -> ArgMatches<'a> {
    App::new("Print text representation of a binary DNS response")
        .version(crate_version!())
        .set_term_width(MAX_TERM_WIDTH)
        .about("\nRead DNS binary response from stdin and print a text representation")
        .get_matches_from(args)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    let _matches = parse_cli_opts(args);

    let mut buf = Vec::new();
    let mut stdin = tokio::io::stdin();
    stdin.read_to_end(&mut buf).await?;

    match Message::from_vec(&buf) {
        Ok(v) => {
            println!("{:?}", v);
        }
        Err(e) => {
            eprintln!("decoding error: {}", e);
        }
    }

    Ok(())
}
