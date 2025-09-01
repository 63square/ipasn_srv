use axum::extract::State;
use axum::routing::post;
use axum::{Router, extract::Json};
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

// -- FORMAT --
// network,country,country_code,continent,continent_code,asn,as_name,as_domain
// 1.0.0.0/24,Australia,AU,Oceania,OC,AS13335,"Cloudflare, Inc.",cloudflare.com

type Record = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

type Table = IpnetTrie<Record>;

fn load_data(data_path: &str) -> Table {
    let mut asn_table: Table = IpnetTrie::new();

    let mut data_reader = csv::Reader::from_path(data_path).expect("unable to read data");

    for result in data_reader.deserialize() {
        let mut record: Record = result.expect("unable to read record");

        if let Ok(network) = IpNet::from_str(&record.0) {
            asn_table.insert(network, record);
        } else {
            record.0.push_str("/32");

            if let Ok(network) = IpNet::from_str(&record.0) {
                asn_table.insert(network, record);
            } else {
                panic!("Invalid network {}", record.0)
            }
        }
    }

    asn_table
}

#[derive(Deserialize)]
struct IpRequest {
    ips: Vec<String>,
}

type IpResults = HashMap<String, Option<Record>>;

async fn handle_bulk_lookup(
    State(state): State<Arc<Table>>,
    Json(payload): Json<IpRequest>,
) -> Json<IpResults> {
    let mut results = IpResults::with_capacity(payload.ips.len());

    for ip_str in payload.ips {
        if let Ok(ip) = IpAddr::from_str(&ip_str) {
            if let Some(result) = state.longest_match(&IpNet::from(ip)) {
                results.insert(ip_str, Some(result.1.clone()));
            } else {
                results.insert(ip_str, None);
            }
        } else {
            results.insert(ip_str, None);
        }
    }

    Json(results)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 2, "Usage: ./server <data.csv>");

    let table = load_data(&args[1]);

    let app = Router::new()
        .route("/", post(handle_bulk_lookup))
        .with_state(table.into());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
