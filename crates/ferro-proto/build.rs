//! Compile the FerroGate gRPC surface (`machine_identity.proto`) into tonic
//! client and server stubs at build time.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/machine_identity.proto");
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/machine_identity.proto"], &["proto"])?;
    Ok(())
}
