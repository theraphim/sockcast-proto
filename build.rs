fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/sshcast/v1/sshcast.proto");
    println!("cargo:rerun-if-env-changed=SSHCAST_REGEN_PROTO");

    #[cfg(feature = "regen-proto")]
    {
        let out_file = std::path::Path::new("src/pb/sshcast.v1.rs");
        let regen = std::env::var("SSHCAST_REGEN_PROTO").is_ok();

        if !out_file.exists() || regen {
            std::fs::create_dir_all("src/pb")?;

            if std::env::var_os("PROTOC").is_none() {
                let local_protoc = std::path::Path::new("/home/stingray/.local/bin/protoc");
                if local_protoc.exists() {
                    std::env::set_var("PROTOC", local_protoc);
                }
            }

            tonic_build::configure()
                .build_server(true)
                .build_client(true)
                .out_dir("src/pb")
                .compile_protos(&["proto/sshcast/v1/sshcast.proto"], &["proto"])?;
        }
    }

    Ok(())
}
