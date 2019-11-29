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

use tokio::prelude::*;
use trust_dns::op::Message;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = Vec::new();
    let mut stdin = tokio::io::stdin();
    let read = stdin.read_to_end(&mut buf).await?;
    if read == 0 {
        eprintln!("error: empty payload, {} bytes read", read);
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

fn format_question(mes: &Message) -> String {
    format!(
        ";; QUESTION SECTION:\n{}",
        mes.queries()
            .iter()
            .map(|q| format!("; {}\t\t{}\t{}", q.name().to_utf8(), q.query_class(), q.query_type()))
            .collect::<Vec<String>>()
            .join(",")
    )
}

fn format_answer(mes: &Message) -> String {
    format!(
        ";; ANSWER SECTION:\n{}",
        mes.answers()
            .iter()
            .map(|a| format!(
                "{}\t{}\t{}\t{}\t{}",
                a.name().to_utf8(),
                a.ttl(),
                a.dns_class(),
                a.record_type(),
                donut::response::record_to_data(a),
            ))
            .collect::<Vec<String>>()
            .join("\n")
    )
}

fn format_query_info(mes: &Message) -> String {
    unimplemented!();
}

fn format_message(mes: &Message) -> String {
    format!("{}\n\n{}", format_question(mes), format_answer(mes))
}
