use axum::extract::State;
use axum::routing::post;
use axum::{Router, extract::Json};
use ipnet::{IpNet, IpSub, Ipv4Net, Ipv6Net};
use ipnet_trie::IpnetTrie;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

type ASNRecord = (IpAddr, IpAddr, u32, String);
type CountryRecord = (IpAddr, IpAddr, String);

type ASNWithCountry = (u32, String, String);

fn parse_network(ip_from: IpAddr, ip_to: IpAddr) -> Option<IpNet> {
    match (ip_from, ip_to) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            let diff = end.saturating_sub(start);
            let leading_zeros = diff.leading_zeros() as u8;

            Some(IpNet::V4(Ipv4Net::new(start, leading_zeros).unwrap()))
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            let diff = end.saturating_sub(start);
            let leading_zeros = diff.leading_zeros() as u8;

            Some(IpNet::V6(Ipv6Net::new(start, leading_zeros).unwrap()))
        }
        _ => None,
    }
}

type ASNTable = IpnetTrie<ASNWithCountry>;
fn load_data(asn_path: &str, country_path: &str) -> ASNTable {
    let mut asn_table: ASNTable = IpnetTrie::new();
    let mut country_table: IpnetTrie<CountryRecord> = IpnetTrie::new();

    let mut asn_data_reader = csv::Reader::from_path(asn_path).expect("unable to read asn data");
    let mut country_data_reader =
        csv::Reader::from_path(country_path).expect("unable to read country data");

    for result in country_data_reader.deserialize() {
        let record: CountryRecord = result.expect("unable to read country record");

        let ip_from: IpAddr = record.0;
        let ip_to: IpAddr = record.1;

        let network = parse_network(ip_from, ip_to).unwrap();

        country_table.insert(network, record);
    }

    let mut skipped = 0;
    for result in asn_data_reader.deserialize() {
        let record: ASNRecord = result.expect("unable to read ASN record");

        let ip_from: IpAddr = record.0;
        let ip_to: IpAddr = record.1;

        let network = parse_network(ip_from, ip_to).unwrap();

        if let Some(found) = &country_table.longest_match(&network) {
            asn_table.insert(network, (record.2, record.3, found.1.2.clone()));
        } else {
            skipped += 1
        }
    }

    println!("Loaded data, skipped {}", skipped);

    asn_table
}

#[derive(Deserialize)]
struct IpRequest {
    ips: Vec<String>,
}

#[derive(Serialize)]
struct IpResult {
    ip: String,
    result: Option<ASNWithCountry>,
}

async fn handle_bulk_lookup(
    State(state): State<Arc<ASNTable>>,
    Json(payload): Json<IpRequest>,
) -> Json<Vec<IpResult>> {
    let mut results = Vec::new();

    for ip_str in payload.ips {
        if let Ok(ip) = IpAddr::from_str(&ip_str) {
            if let Some(result) = state.longest_match(&IpNet::from(ip)) {
                results.push(IpResult {
                    ip: ip_str,
                    result: Some(result.1.clone()),
                });
            } else {
                results.push(IpResult {
                    ip: ip_str,
                    result: None,
                });
            }
        } else {
            results.push(IpResult {
                ip: ip_str,
                result: None,
            });
        }
    }

    Json(results)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 3, "Usage: ./server <asn.csv> <country.csv>");

    let asn_table = load_data(&args[1], &args[2]);

    let app = Router::new()
        .route("/", post(handle_bulk_lookup))
        .with_state(asn_table.into());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
