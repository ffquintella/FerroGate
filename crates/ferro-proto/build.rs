//! Compile the FerroGate gRPC surface (`machine_identity.proto` and the F20
//! administrator surface `admin.proto`) into tonic client and server stubs at
//! build time, and emit the combined file descriptor set so CMIS can prove at
//! test time that every RPC is classified in its access table.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/machine_identity.proto");
    println!("cargo:rerun-if-changed=proto/admin.proto");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(out_dir.join("ferrogate_descriptor.bin"))
        .compile_protos(
            &["proto/machine_identity.proto", "proto/admin.proto"],
            &["proto"],
        )?;
    Ok(())
}
