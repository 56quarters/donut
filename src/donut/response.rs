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

use crate::types::DonutResult;
use serde::Serialize;
use trust_dns::op::DnsResponse;
use trust_dns::proto::serialize::binary::BinEncodable;
use trust_dns::rr::{RData, Record};

///
///
///
#[derive(Debug, Default, Clone)]
pub struct ResponseEncoderJson;

impl ResponseEncoderJson {
    ///
    ///
    ///
    pub fn new() -> Self {
        ResponseEncoderJson
    }

    ///
    ///
    ///
    pub async fn encode(&self, res: DnsResponse) -> DonutResult<Vec<u8>> {
        let questions: Vec<JsonQuestion> = res
            .queries()
            .iter()
            .map(|query| JsonQuestion::new(query.name().to_utf8(), u16::from(query.query_type())))
            .collect();

        let answers: Vec<JsonAnswer> = res
            .answers()
            .iter()
            .map(|record| {
                let data = record_to_data(record);
                JsonAnswer::new(
                    record.name().to_utf8(),
                    u16::from(record.record_type()),
                    record.ttl(),
                    data,
                )
            })
            .collect();

        Ok(serde_json::to_vec(&JsonResponse::new(
            u16::from(res.response_code()),
            res.truncated(),
            res.recursion_desired(),
            res.recursion_available(),
            false,
            true,
            questions,
            answers,
        ))?)
    }
}

pub fn record_to_data(record: &Record) -> String {
    match record.rdata() {
        RData::A(v) => v.to_string(),
        RData::AAAA(v) => v.to_string(),
        RData::ANAME(v) => v.to_string(),
        //RData::CAA(v) => ,
        RData::CNAME(v) => v.to_string(),
        RData::MX(v) => format!("{} {}", v.preference(), v.exchange()),
        //RData::NAPTR(v) => ,
        RData::NS(v) => v.to_string(),
        //RData::NULL(v) =>  ,
        //RData::OPENPGPKEY(v) => ,
        //RData::OPT(v) => ,
        RData::PTR(v) => v.to_string(),
        RData::SOA(v) => format!(
            "{} {} {} {} {} {} {}",
            v.mname().to_string(),
            v.rname().to_string(),
            v.serial(),
            v.refresh(),
            v.retry(),
            v.expire(),
            v.minimum(),
        ),
        RData::SRV(v) => format!("{} {} {} {}", v.priority(), v.weight(), v.port(), v.target()),
        //RData::SSHFP(v) => ,
        //RData::TLSA(v) => ,
        RData::TXT(v) => format!(
            "\"{}\"",
            v.txt_data()
                .iter()
                .flat_map(|t| String::from_utf8(t.to_vec()))
                .collect::<Vec<String>>()
                .concat()
        ),
        _ => panic!("Unexpected result: {:?}", record),
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
struct JsonQuestion {
    #[serde(rename = "name")]
    name: String,

    #[serde(rename = "type")]
    kind: u16,
}

impl JsonQuestion {
    fn new<S>(name: S, kind: u16) -> Self
    where
        S: Into<String>,
    {
        JsonQuestion {
            name: name.into(),
            kind,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
struct JsonAnswer {
    #[serde(rename = "name")]
    name: String,

    #[serde(rename = "type")]
    kind: u16,

    #[serde(rename = "TTL")]
    ttl: u32,

    #[serde(rename = "data")]
    data: String,
}

impl JsonAnswer {
    fn new<S1, S2>(name: S1, kind: u16, ttl: u32, data: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        JsonAnswer {
            name: name.into(),
            kind,
            ttl,
            data: data.into(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct JsonResponse {
    #[serde(rename = "Status")]
    status: u16,

    #[serde(rename = "TC")]
    truncated: bool,

    #[serde(rename = "RD")]
    recursion_desired: bool,

    #[serde(rename = "RA")]
    recursion_available: bool,

    #[serde(rename = "AD")]
    all_validated: bool,

    #[serde(rename = "CD")]
    checking_disabled: bool,

    #[serde(rename = "Question")]
    questions: Vec<JsonQuestion>,

    #[serde(rename = "Answer")]
    answers: Vec<JsonAnswer>,
}

impl JsonResponse {
    #[allow(clippy::too_many_arguments)]
    fn new(
        status: u16,
        truncated: bool,
        recursion_desired: bool,
        recursion_available: bool,
        all_validated: bool,
        checking_disabled: bool,
        questions: Vec<JsonQuestion>,
        answers: Vec<JsonAnswer>,
    ) -> Self {
        JsonResponse {
            status,
            truncated,
            recursion_desired,
            recursion_available,
            all_validated,
            checking_disabled,
            questions,
            answers,
        }
    }
}

///
///
///
#[derive(Debug, Default, Clone)]
pub struct ResponseEncoderWire;

impl ResponseEncoderWire {
    ///
    ///
    ///
    pub fn new() -> Self {
        ResponseEncoderWire
    }

    ///
    ///
    ///
    pub async fn encode(&self, res: DnsResponse) -> DonutResult<Vec<u8>> {
        Ok(res.to_bytes()?)
    }
}
