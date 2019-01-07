#[macro_use]
extern crate serde_derive;

use std::collections::BTreeMap;

use clap::*;

use opcua_types::Variant;

mod play;
mod record;

#[derive(Serialize, Deserialize)]
struct ChangeRecord {
    /// Timestamp
    timestamp: i64,
    /// Variable id
    id: u32,
    /// Value
    value: Variant,
    /// Status code
    status_code: u32,
}

/// Serializable recording file, written
#[derive(Serialize, Deserialize)]
struct RecordingFile {
    /// An id mapping between
    variables: BTreeMap<u32, String>,
    /// A list of change records
    records: Vec<ChangeRecord>,
}

fn main() {
    let matches = App::new("OPC UA Certificate Creator")
        .author("Adam Lock <locka99@gmail.com>")
        .about("OPC UA Recorder")
        .arg(Arg::with_name("record")
            .long("record")
            .help("Connect to OPC UA server and record values")
            .value_name("record"))
        .arg(Arg::with_name("play")
            .long("play")
            .help("Run as an OPC UA server and play values")
            .value_name("play"))
        .get_matches();

    if matches.is_present("record") || matches.is_present("play") {
        eprintln!("Must specify --record or --play");
    } else if matches.is_present("record") {
        record::main(&matches);
    } else if matches.is_present("play") {
        play::main(&matches);
    } else {
        eprintln!("Must specify --record or --play");
    }
}
