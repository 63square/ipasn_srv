use flate2::read::GzDecoder;
use indexmap::IndexSet;
use ip_network_table_deps_treebitmap::IpLookupTable;
use ipnet::IpNet;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::Server;
use tonic::{Request, Status};
use tonic::{Response, Streaming};

use crate::pb::{IpQuery, IpResult};

mod pb {
    tonic::include_proto!("grpc.ipasn.lookup");
}

struct U24(u8, u8, u8);

impl U24 {
    pub fn new(x: u32) -> U24 {
        assert!(x <= 0xFFFFFF, "out of bounds");
        U24((x >> 16) as u8, ((x >> 8) & 0xFF) as u8, (x & 0xFF) as u8)
    }

    pub fn read(&self) -> u32 {
        return ((self.0 as u32) << 16) | ((self.1 as u32) << 8) | self.2 as u32;
    }
}

struct IPTable {
    ipv4_table: IpLookupTable<Ipv4Addr, U24>,
    ipv6_table: IpLookupTable<Ipv6Addr, U24>,
}

impl IPTable {
    pub fn with_capacity(ipv4_capacity: usize, ipv6_capacity: usize) -> Self {
        Self {
            ipv4_table: IpLookupTable::with_capacity(ipv4_capacity),
            ipv6_table: IpLookupTable::with_capacity(ipv6_capacity),
        }
    }

    pub fn insert(&mut self, network: &IpNet, value: U24) {
        match network {
            IpNet::V4(net) => self
                .ipv4_table
                .insert(net.network(), net.prefix_len().into(), value),
            IpNet::V6(net) => self
                .ipv6_table
                .insert(net.network(), net.prefix_len().into(), value),
        };
    }

    pub fn get(&self, ip: &IpAddr) -> Option<(IpNet, &U24)> {
        match ip {
            IpAddr::V4(addr) => {
                if let Some((found_addr, prefix, value)) = self.ipv4_table.longest_match(*addr) {
                    Some((
                        IpNet::new(IpAddr::V4(found_addr), prefix as u8).unwrap(),
                        value,
                    ))
                } else {
                    None
                }
            }
            IpAddr::V6(addr) => {
                if let Some((found_addr, prefix, value)) = self.ipv6_table.longest_match(*addr) {
                    Some((
                        IpNet::new(IpAddr::V6(found_addr), prefix as u8).unwrap(),
                        value,
                    ))
                } else {
                    None
                }
            }
        }
    }
}

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
    continent: u8,
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
    table: IPTable,
    continents: IndexSet<ContinentInfo>,
    countries: IndexSet<CountryInfo>,
    asns: IndexSet<ASInfo>,
    ip_data: IndexSet<u32>,
}

const ASN_SHIFT: u32 = 8;

fn pack_ip_info(asn: u32, country: u8) -> u32 {
    (asn << ASN_SHIFT) | country as u32
}

fn unpack_ip_info(code: u32) -> (u32, u8) {
    let country = (code & 0xFF) as u8;
    let asn = code >> ASN_SHIFT;

    (asn, country)
}

#[derive(Debug, serde::Deserialize)]
struct Record {
    network: String,
    country: String,
    country_code: String,
    continent: String,
    continent_code: String,
    asn: Option<String>,
    as_name: Option<String>,
    as_domain: Option<String>,
}

fn load_data(data_path: &str) -> IPData {
    let mut table = IPTable::with_capacity(1500000, 4500000);
    let mut continents: IndexSet<ContinentInfo> = IndexSet::with_capacity(7);
    let mut countries: IndexSet<CountryInfo> = IndexSet::with_capacity(250);
    let mut asns: IndexSet<ASInfo> = IndexSet::with_capacity(80000);
    let mut ip_data: IndexSet<u32> = IndexSet::with_capacity(150000);

    let file = File::open(Path::new(data_path)).expect("unable to read file");

    let gz_decoder = GzDecoder::new(file);
    let reader = BufReader::new(gz_decoder);

    let mut rdr = csv::Reader::from_reader(reader);
    for result in rdr.deserialize() {
        let record: Record = result.expect("unable to parse record");

        let mut country_info = CountryInfo {
            country: record.country,
            country_code: record.country_code.as_bytes().try_into().unwrap(),
            continent: 0,
        };

        let country = if let Some((country_index, _)) = countries.get_full(&country_info) {
            country_index
        } else {
            let (continent, _) = continents.insert_full(ContinentInfo {
                continent: record.continent,
                continent_code: record.continent_code.as_bytes().try_into().unwrap(),
            });

            country_info.continent = continent as u8;

            let (country_index, _) = countries.insert_full(country_info);
            country_index
        };

        let as_info = if let (Some(asn), Some(as_name), Some(as_domain)) =
            (record.asn, record.as_name, record.as_domain)
        {
            ASInfo {
                asn: if asn.len() > 2 {
                    asn[2..].parse().expect("Invalid AS number")
                } else {
                    panic!("Invalid AS: {}", asn);
                },
                as_name,
                as_domain,
            }
        } else {
            ASInfo {
                asn: 0,
                as_name: String::new(),
                as_domain: String::new(),
            }
        };

        let (asn, _) = asns.insert_full(as_info);

        let ip_info = pack_ip_info(asn.try_into().unwrap(), country.try_into().unwrap());
        let (ip_index, _) = ip_data.insert_full(ip_info);

        if let Ok(network) = IpNet::from_str(&record.network) {
            table.insert(&network, U24::new(ip_index as u32));
        } else {
            let mut network_clone = record.network.clone();
            network_clone.push_str("/32");

            if let Ok(network) = IpNet::from_str(&network_clone) {
                table.insert(&network, U24::new(ip_index as u32));
            } else {
                panic!("Invalid network {}", &record.network)
            }
        }
    }

    println!("{} unique entries", ip_data.len());

    IPData {
        table,
        continents,
        countries,
        asns,
        ip_data,
    }
}

fn to_record(ip_data: &IPData, network: IpNet, ip_info: &U24) -> Option<pb::IpResponse> {
    let ip_index: u32 = ip_info.read();

    let (asn, country) = unpack_ip_info(
        *ip_data
            .ip_data
            .get_index(ip_index.try_into().unwrap())
            .unwrap(),
    );

    let country_info = ip_data.countries.get_index(country as usize)?;
    let as_info = ip_data.asns.get_index(asn as usize)?;
    let continent_info = ip_data
        .continents
        .get_index(country_info.continent as usize)?;

    Some(pb::IpResponse {
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

struct LookupServer {
    ip_data: Arc<IPData>,
}

#[tonic::async_trait]
impl pb::lookup_server::Lookup for LookupServer {
    type LookupManyStream = Pin<Box<dyn Stream<Item = Result<pb::IpResult, Status>> + Send>>;

    async fn lookup_single(&self, req: Request<IpQuery>) -> Result<Response<pb::IpResult>, Status> {
        let ip = req.into_inner().ip;

        let response = if let Ok(parsed_ip) = IpAddr::from_str(&ip) {
            if let Some(found) = self.ip_data.table.get(&parsed_ip) {
                to_record(&self.ip_data, found.0, found.1)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Response::new(IpResult { response, ip }))
    }

    async fn lookup_many(
        &self,
        req: tonic::Request<Streaming<IpQuery>>,
    ) -> Result<Response<Self::LookupManyStream>, Status> {
        let mut in_stream = req.into_inner();
        let (tx, rx) = mpsc::channel(128);

        let ip_data = Arc::clone(&self.ip_data);

        tokio::spawn(async move {
            while let Some(result) = in_stream.next().await {
                match result {
                    Ok(v) => {
                        let response = if let Ok(parsed_ip) = IpAddr::from_str(&v.ip) {
                            if let Some(found) = ip_data.table.get(&parsed_ip) {
                                to_record(&ip_data, found.0, found.1)
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        tx.send(Ok(IpResult { response, ip: v.ip }))
                            .await
                            .expect("working rx");
                    }
                    Err(err) => match tx.send(Err(err)).await {
                        Ok(_) => (),
                        Err(_err) => break,
                    },
                }
            }
        });

        let out_stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(out_stream) as Self::LookupManyStream))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 2, "Usage: ./server <data.csv.gz>");

    println!("Starting...");

    let ip_data = load_data(&args[1]);

    println!("Data loaded successfully");
    println!(
        "Continents: {} | Countries: {} | ASNs: {}",
        ip_data.continents.len(),
        ip_data.countries.len(),
        ip_data.asns.len()
    );

    let server = LookupServer {
        ip_data: ip_data.into(),
    };

    Server::builder()
        .add_service(pb::lookup_server::LookupServer::new(server))
        .serve("127.0.0.1:36841".to_socket_addrs().unwrap().next().unwrap())
        .await
        .unwrap();

    Ok(())
}
