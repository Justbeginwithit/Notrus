use std::io::{Read, Write};

fn main() {
    if let Err(error) = run() {
        let payload = serde_json::json!({
            "error": error,
        });
        let _ = writeln!(std::io::stderr(), "{payload}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("Unable to read helper input: {error}"))?;
    let request: notrus_protocol_core::bridge::BridgeRequest =
        serde_json::from_str(&input).map_err(|error| format!("Invalid helper request: {error}"))?;
    let response = notrus_protocol_core::bridge::handle_request(request)?;
    serde_json::to_writer(std::io::stdout(), &response)
        .map_err(|error| format!("Unable to write helper response: {error}"))?;
    Ok(())
}
