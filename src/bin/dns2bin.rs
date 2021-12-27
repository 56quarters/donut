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

use clap::{crate_version, Parser};
use std::env;
use std::io::{self, Write};
use trust_dns_client::op::{Message, Query};
use trust_dns_client::rr::{Name, RecordType};
use trust_dns_client::serialize::binary::BinEncodable;

/// Donut DNS request to binary util
///
/// Output a DNS request in base64 or binary representation
#[derive(Debug, Parser)]
#[clap(name = "donut", version = crate_version!())]
struct Dns2BinApplication {
    /// Output raw binary (instead of base64 text)
    #[clap(long = "raw", short = 'r')]
    raw: bool,

    /// Record type to lookup
    #[clap(long = "type", short = 't', default_value_t = RecordType::A)]
    type_: RecordType,

    /// Domain name to generate a binary request for
    name: Name,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let opts = Dns2BinApplication::parse();

    let bytes = Message::new()
        .add_query(Query::query(opts.name.clone(), opts.type_))
        .to_bytes()
        .map(|b| {
            if !opts.raw {
                base64::encode_config(&b, base64::URL_SAFE_NO_PAD).into_bytes()
            } else {
                b
            }
        })?;

    let mut stdout = io::stdout();
    stdout.write_all(&bytes)?;

    Ok(())
}
