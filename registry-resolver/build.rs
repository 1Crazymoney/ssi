fn main() -> Result<(), Box<dyn std::error::Error>> {
    let package_path = "buf.build/knox-networks/registry-mgmt";
    std::process::Command::new("buf")
        .arg("generate")
        .arg(package_path)
        .spawn()?;
    Ok(())
}
