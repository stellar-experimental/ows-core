use crate::CliError;

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    xdr: &str,
    encoding: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let passphrase = super::peek_passphrase();
    let result = ows_lib::sign_auth_entry(
        wallet_name,
        chain_str,
        xdr,
        passphrase.as_deref(),
        Some(encoding),
        Some(index),
        None,
    )?;

    if json_output {
        let obj = serde_json::json!({
            "address": result.address,
            "public_key": result.public_key,
            "payload_hash": result.payload_hash,
            "signature": result.signature,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", result.signature);
    }

    Ok(())
}
