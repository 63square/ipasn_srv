use indexmap::IndexSet;
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

struct IpInfo {
    network: String,
    country: usize,
    asn: usize,
}

type Table = IpnetTrie<IpInfo>;

#[derive(Eq, Hash, PartialEq)]
struct CountryInfo {
    country: String,
    country_code: String,
    continent: String,
    continent_code: String,
}

#[derive(Eq, Hash, PartialEq)]
struct ASInfo {
    asn: String,
    as_name: String,
    as_domain: String,
}

struct IPData {
    table: Table,
    countries: IndexSet<CountryInfo>,
    asns: IndexSet<ASInfo>,
}

fn load_data(data_path: &str) -> IPData {
    let mut table: IpnetTrie<IpInfo> = IpnetTrie::new();
    let mut countries: IndexSet<CountryInfo> = IndexSet::with_capacity(200);
    let mut asns: IndexSet<ASInfo> = IndexSet::with_capacity(150000);

    let mut data_reader = csv::Reader::from_path(data_path).expect("unable to read data");

    for result in data_reader.deserialize() {
        let mut record: Record = result.expect("unable to read record");

        if let Ok(network) = IpNet::from_str(&record.0) {
            let (country, _) = countries.insert_full(CountryInfo {
                country: record.1,
                country_code: record.2,
                continent: record.3,
                continent_code: record.4,
            });
            let (asn, _) = asns.insert_full(ASInfo {
                asn: record.5,
                as_name: record.6,
                as_domain: record.7,
            });

            table.insert(
                network,
                IpInfo {
                    network: record.0,
                    country,
                    asn,
                },
            );
        } else {
            record.0.push_str("/32");

            if let Ok(network) = IpNet::from_str(&record.0) {
                let (country, _) = countries.insert_full(CountryInfo {
                    country: record.1,
                    country_code: record.2,
                    continent: record.3,
                    continent_code: record.4,
                });
                let (asn, _) = asns.insert_full(ASInfo {
                    asn: record.5,
                    as_name: record.6,
                    as_domain: record.7,
                });

                table.insert(
                    network,
                    IpInfo {
                        network: record.0,
                        country,
                        asn,
                    },
                );
            } else {
                panic!("Invalid network {}", record.0)
            }
        }
    }

    IPData {
        table,
        countries,
        asns,
    }
}

fn to_record(ip_data: &IPData, ip_info: &IpInfo) -> Option<protos::IpRecord> {
    let country_info = ip_data.countries.get_index(ip_info.country)?;
    let as_info = ip_data.asns.get_index(ip_info.asn)?;

    Some(protos::IpRecord {
        network: ip_info.network.clone(),
        country: country_info.country.clone(),
        country_code: country_info.country_code.clone(),
        continent: country_info.continent.clone(),
        continent_code: country_info.continent_code.clone(),
        asn: as_info.asn.clone(),
        as_name: as_info.as_name.clone(),
        as_domain: as_info.as_domain.clone(),
    })
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 2, "Usage: ./server <data.csv>");

    let ip_data = load_data(&args[1]);

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
                    if let Some(found) = ip_data.table.longest_match(&network) {
                        response.results.insert(
                            ip,
                            protos::IpResult {
                                record: to_record(&ip_data, found.1),
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
