fn main() {
    prost_build::Config::new()
        .out_dir("src/protos")
        .compile_protos(&["protos/lookup.proto"], &["protos"])
        .unwrap();
}
