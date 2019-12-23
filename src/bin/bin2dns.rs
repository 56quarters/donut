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
use std::fmt::Write;
use tokio::prelude::*;
use trust_dns::op::Message;
use trust_dns::rr::Record;

const MAX_TERM_WIDTH: usize = 72;

fn parse_cli_opts<'a>(args: Vec<String>) -> ArgMatches<'a> {
    App::new("Donut binary to text util")
        .version(crate_version!())
        .set_term_width(MAX_TERM_WIDTH)
        .about("\nConvert binary DNS responses to a dig-like text format")
        .get_matches_from(args)
}

fn format_question(buf: &mut String, mes: &Message) {
    let _ = writeln!(buf, ";; QUESTION SECTION:");
    for q in mes.queries() {
        let _ = writeln!(
            buf,
            "; {}\t\t\t{}\t{}",
            q.name().to_utf8(),
            q.query_class(),
            q.query_type()
        );
    }
}

fn format_authority(buf: &mut String, mes: &Message) {
    let _ = writeln!(buf, ";; AUTHORITY SECTION:");
    format_records(buf, mes.name_servers());
}

fn format_answer(buf: &mut String, mes: &Message) {
    let _ = writeln!(buf, ";; ANSWER SECTION:");
    format_records(buf, mes.answers());
}

fn format_records(buf: &mut String, records: &[Record]) {
    for r in records {
        let _ = writeln!(
            buf,
            "{}\t\t{}\t{}\t{}\t{}",
            r.name().to_utf8(),
            r.ttl(),
            r.dns_class(),
            r.record_type(),
            donut::response::record_to_data(r),
        );
    }
}

fn format_message(mes: &Message) -> String {
    let mut buf = String::new();
    format_question(&mut buf, mes);
    let _ = writeln!(buf);

    if mes.answer_count() > 0 {
        format_answer(&mut buf, mes);
    } else {
        format_authority(&mut buf, mes)
    }

    buf
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    let _ = parse_cli_opts(args);

    let mut buf = Vec::new();
    let mut stdin = tokio::io::stdin();
    let read = stdin.read_to_end(&mut buf).await?;
    if read == 0 {
        eprintln!("read error: empty payload, {} bytes read", read);
        return Ok(());
    }

    match Message::from_vec(&buf) {
        Ok(v) => {
            println!("{}", format_message(&v));
        }
        Err(e) => {
            eprintln!("decoding error: {}", e);
        }
    }

    Ok(())
}
