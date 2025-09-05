use indexmap::IndexSet;
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use prost::Message;
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::ops::Deref;
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

type IpInfo = u32;
type Table = IpnetTrie<IpInfo>;

#[derive(Eq, PartialEq)]
struct ContinentInfo {
    continent: String,
    continent_code: [u8; 2],
}

impl std::hash::Hash for ContinentInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.continent_code.hash(state);
    }
}

#[derive(Eq, PartialEq)]
struct CountryInfo {
    country: String,
    country_code: [u8; 2],
}

impl std::hash::Hash for CountryInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.country_code.hash(state);
    }
}

#[derive(Eq, PartialEq)]
struct ASInfo {
    asn: u32,
    as_name: String,
    as_domain: String,
}

impl std::hash::Hash for ASInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.asn.hash(state);
    }
}

struct IPData {
    table: Table,
    continents: IndexSet<ContinentInfo>,
    countries: IndexSet<CountryInfo>,
    asns: IndexSet<ASInfo>,
}

const CONTINENT_BITS: u32 = 4;
const COUNTRY_BITS: u32 = 8;
const ASN_SHIFT: u32 = CONTINENT_BITS + COUNTRY_BITS;

fn pack_ip_info(asn: u32, country: u8, continent: u8) -> IpInfo {
    (asn << (COUNTRY_BITS + CONTINENT_BITS))
        | ((country as u32) << CONTINENT_BITS)
        | (continent as u32)
}

fn unpack_ip_info(ip_info: IpInfo) -> (u32, u8, u8) {
    let continent = (ip_info & 0xF) as u8;
    let country = ((ip_info >> CONTINENT_BITS) & 0xFF) as u8;
    let asn = ip_info >> ASN_SHIFT;
    (asn, country, continent)
}

fn load_data(data_path: &str) -> IPData {
    let mut table: IpnetTrie<IpInfo> = IpnetTrie::new();
    let mut continents: IndexSet<ContinentInfo> = IndexSet::with_capacity(8);
    let mut countries: IndexSet<CountryInfo> = IndexSet::with_capacity(255);
    let mut asns: IndexSet<ASInfo> = IndexSet::with_capacity(150000);

    let mut data_reader = csv::Reader::from_path(data_path).expect("unable to read data");

    for result in data_reader.deserialize() {
        let mut record: Record = result.expect("unable to read record");

        if let Ok(network) = IpNet::from_str(&record.0) {
            let (continent, _) = continents.insert_full(ContinentInfo {
                continent: record.3,
                continent_code: record.4.into_bytes().try_into().unwrap(),
            });
            let (country, _) = countries.insert_full(CountryInfo {
                country: record.1,
                country_code: record.2.into_bytes().try_into().unwrap(),
            });

            let (asn, _) = asns.insert_full(ASInfo {
                asn: if record.5.len() > 2 {
                    record.5[2..].parse().unwrap_or(0)
                } else {
                    0
                },
                as_name: record.6,
                as_domain: record.7,
            });

            let ip_info = pack_ip_info(
                asn.try_into().unwrap(),
                country.try_into().unwrap(),
                continent.try_into().unwrap(),
            );

            table.insert(network, ip_info);
        } else {
            record.0.push_str("/32");

            if let Ok(network) = IpNet::from_str(&record.0) {
                let (continent, _) = continents.insert_full(ContinentInfo {
                    continent: record.3,
                    continent_code: record.4.into_bytes().try_into().unwrap(),
                });
                let (country, _) = countries.insert_full(CountryInfo {
                    country: record.1,
                    country_code: record.2.into_bytes().try_into().unwrap(),
                });
                let (asn, _) = asns.insert_full(ASInfo {
                    asn: if record.5.len() > 2 {
                        record.5[2..].parse().unwrap_or(0)
                    } else {
                        0
                    },
                    as_name: record.6,
                    as_domain: record.7,
                });

                let ip_info = pack_ip_info(
                    asn.try_into().unwrap(),
                    country.try_into().unwrap(),
                    continent.try_into().unwrap(),
                );

                table.insert(network, ip_info);
            } else {
                panic!("Invalid network {}", record.0)
            }
        }
    }

    IPData {
        table,
        continents,
        countries,
        asns,
    }
}

fn to_record(ip_data: &IPData, network: IpNet, ip_info: IpInfo) -> Option<protos::IpRecord> {
    let (asn, country, continent) = unpack_ip_info(ip_info);

    let country_info = ip_data.countries.get_index(country as usize)?;
    let as_info = ip_data.asns.get_index(asn as usize)?;
    let continent_info = ip_data.continents.get_index(continent as usize)?;

    Some(protos::IpRecord {
        network: network.to_string(),
        country: country_info.country.clone(),
        country_code: String::from_utf8(country_info.country_code.to_vec()).unwrap(),
        continent: continent_info.continent.clone(),
        continent_code: String::from_utf8(continent_info.continent_code.to_vec()).unwrap(),
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
    println!(
        "Continents: {} | Countries: {} | ASNs: {}",
        ip_data.continents.len(),
        ip_data.countries.len(),
        ip_data.asns.len()
    );

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
                                record: to_record(&ip_data, found.0, *found.1),
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
