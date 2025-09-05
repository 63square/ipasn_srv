fn main() {
    tonic_prost_build::configure()
        .compile_protos(&["proto/lookup.proto"], &["proto"])
        .unwrap();
}
