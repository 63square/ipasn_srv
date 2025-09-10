use arrow::array::{Array, StringArray};
use indexmap::IndexSet;
use ip_network_table_deps_treebitmap::IpLookupTable;
use ipnet::IpNet;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::env;
use std::fs::File;
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
    pub fn new() -> Self {
        Self {
            ipv4_table: IpLookupTable::new(),
            ipv6_table: IpLookupTable::new(),
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

fn load_data(data_path: &str) -> IPData {
    let mut table = IPTable::new();

    let mut continents: IndexSet<ContinentInfo> = IndexSet::with_capacity(7);
    let mut countries: IndexSet<CountryInfo> = IndexSet::with_capacity(246);
    let mut asns: IndexSet<ASInfo> = IndexSet::with_capacity(72840);
    let mut ip_data: IndexSet<u32> = IndexSet::with_capacity(105346);

    let file = File::open(Path::new(data_path)).expect("unable to read file");

    let mut arrow_reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("unable to read parquet")
        .build()
        .unwrap();

    while let Some(batch) = arrow_reader.next() {
        let batch = batch.unwrap();

        let network_array = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let country_array = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let country_code_array = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let continent_array = batch
            .column(3)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let continent_code_array = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let asn_array = batch
            .column(5)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let as_name_array = batch
            .column(6)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let as_domain_array = batch
            .column(7)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        for i in 0..batch.num_rows() {
            let record_network = network_array.value(i);

            let record_country = country_array.value(i);
            let record_country_code = country_code_array.value(i);

            let record_continent = continent_array.value(i);
            let record_continent_code = continent_code_array.value(i);

            let mut country_info = CountryInfo {
                country: record_country.to_owned(),
                country_code: record_country_code.as_bytes().try_into().unwrap(),
                continent: 0,
            };

            let country = if let Some((country_index, _)) = countries.get_full(&country_info) {
                country_index
            } else {
                let (continent, _) = continents.insert_full(ContinentInfo {
                    continent: record_continent.to_owned(),
                    continent_code: record_continent_code.as_bytes().try_into().unwrap(),
                });

                country_info.continent = continent as u8;

                let (country_index, _) = countries.insert_full(country_info);
                country_index
            };

            let as_info = if !asn_array.is_null(i) {
                let record_asn = asn_array.value(i);
                let record_as_name = as_name_array.value(i);
                let record_as_domain = as_domain_array.value(i);

                ASInfo {
                    asn: if record_asn.len() > 2 {
                        record_asn.parse().unwrap_or(0)
                    } else {
                        0
                    },
                    as_name: record_as_name.to_owned(),
                    as_domain: record_as_domain.to_owned(),
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

            if let Ok(network) = IpNet::from_str(record_network) {
                table.insert(&network, U24::new(ip_index as u32));
            } else {
                let mut network_clone = record_network.to_string();
                network_clone.push_str("/32");

                if let Ok(network) = IpNet::from_str(&network_clone) {
                    table.insert(&network, U24::new(ip_index as u32));
                } else {
                    panic!("Invalid network {}", record_network)
                }
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
    assert!(args.len() == 2, "Usage: ./server <data.parquet>");

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
