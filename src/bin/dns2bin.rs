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

use clap::{crate_version, value_t_or_exit, App, Arg, ArgMatches};
use std::env;
use std::io::{self, Write};
use trust_dns::op::{Message, Query};
use trust_dns::rr::{Name, RecordType};
use trust_dns::serialize::binary::BinEncodable;

const MAX_TERM_WIDTH: usize = 72;

fn parse_cli_opts<'a>(args: Vec<String>) -> ArgMatches<'a> {
    App::new("Donut DNS request to binary util")
        .version(crate_version!())
        .set_term_width(MAX_TERM_WIDTH)
        .about("\nOutput a DNS request in base64 or binary representation")
        .arg(
            Arg::with_name("raw")
                .short("r")
                .long("raw")
                .help("Output raw binary (instead of base64)"),
        )
        .arg(
            Arg::with_name("type")
                .short("t")
                .long("type")
                .default_value("A")
                .help("Record type to lookup"),
        )
        .arg(
            Arg::with_name("name")
                .help("Domain name to generate a binary request for")
                .index(1),
        )
        .get_matches_from(args)
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    let matches = parse_cli_opts(args);

    let raw = matches.is_present("raw");
    let name = value_t_or_exit!(matches, "name", Name);
    let record_type = value_t_or_exit!(matches, "type", RecordType);

    let bytes = Message::new()
        .add_query(Query::query(name, record_type))
        .to_bytes()
        .map(|b| {
            if !raw {
                base64::encode_config(&b, base64::URL_SAFE_NO_PAD).into_bytes()
            } else {
                b
            }
        })
        // TODO: Our error type doesn't implement Error (only Fail) and
        // there are conflicting traits when we try (failure seems to have
        // a default impl... but we still get type errors here with `?`).
        .unwrap();

    let mut stdout = io::stdout();
    stdout.write_all(&bytes)?;

    Ok(())
}
