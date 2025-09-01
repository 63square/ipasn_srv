use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use prost::Message;
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::io;

mod protos {
    include!("protos/_.rs");
}

type Record = (String, String, String, String, String, String, String);

type Table = IpnetTrie<protos::IpRecord>;

fn record_convert(record: Record) -> protos::IpRecord {
    protos::IpRecord {
        network: record.0,
        country: record.1,
        country_code: record.2,
        continent: record.3,
        asn: record.4,
        as_name: record.5,
        as_domain: record.6,
    }
}

fn load_data(data_path: &str) -> Table {
    let mut asn_table: Table = IpnetTrie::new();

    let mut data_reader = csv::Reader::from_path(data_path).expect("unable to read data");

    for result in data_reader.deserialize() {
        let mut record: Record = result.expect("unable to read record");

        if let Ok(network) = IpNet::from_str(&record.0) {
            asn_table.insert(network, record_convert(record));
        } else {
            record.0.push_str("/32");

            if let Ok(network) = IpNet::from_str(&record.0) {
                asn_table.insert(network, record_convert(record));
            } else {
                panic!("Invalid network {}", record.0)
            }
        }
    }

    asn_table
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 2, "Usage: ./server <data.csv>");

    let table = load_data(&args[1]);

    println!("Data loaded successfully");

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:36841").await?;
    let mut buf = [0u8; 65535];

    println!("Listening for requests");

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;

        let mut response: protos::IpLookupResponse = protos::IpLookupResponse {
            results: HashMap::new(),
        };

        if let Ok(request) = protos::IpLookupRequest::decode(&buf[..len]) {
            for ip in request.ips {
                if let Ok(parsed_ip) = IpAddr::from_str(&ip) {
                    let network = IpNet::from(parsed_ip);
                    if let Some(found) = table.longest_match(&network) {
                        response.results.insert(
                            ip,
                            protos::IpResult {
                                record: Some(found.1.clone()),
                            },
                        );
                    } else {
                        response
                            .results
                            .insert(ip, protos::IpResult { record: None });
                    }
                } else {
                    response
                        .results
                        .insert(ip, protos::IpResult { record: None });
                }
            }
        }

        let response = response.encode_to_vec();
        let _ = sock.send_to(&response, addr).await?;
    }
}
