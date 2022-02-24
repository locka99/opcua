// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2022 Adam Lock

//! This simple OPC UA client will do the following:
//!
//! 1. Create a client configuration
//! 2. Connect to an endpoint specified by the url with security None
//! 3. Subscribe to values and loop forever printing out their values
use std::sync::{Arc, RwLock};

use opcua_client::prelude::*;

struct Args {
    help: bool,
    url: String,
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();
        Ok(Args {
            help: args.contains(["-h", "--help"]),
            url: args
                .opt_value_from_str("--url")?
                .unwrap_or_else(|| String::from(DEFAULT_URL)),
        })
    }

    pub fn usage() {
        println!(
            r#"Simple Client
Usage:
  -h, --help   Show help
  --url [url]  Url to connect to (default: {})"#,
            DEFAULT_URL
        );
    }
}

const DEFAULT_URL: &str = "opc.tcp://localhost:4855";

fn main() -> Result<(), ()> {
    // Read command line arguments
    let args = Args::parse_args().map_err(|_| Args::usage())?;
    if args.help {
        Args::usage();
        return Ok(());
    }

    // Optional - enable OPC UA logging
    opcua_console_logging::init();

    println!("Creating client");
    // Make the client configuration
    let mut client = ClientBuilder::new()
        .application_name("Browse Client")
        .application_uri("urn:BrowseClient")
        .product_uri("urn:BrowseClient")
        .trust_server_certs(true)
        .create_sample_keypair(true)
        .session_retry_limit(3)
        .session_timeout(1000)
        .client()
        .unwrap();

    println!("Connecting to endpoint {}", args.url);
    let session = client.connect_to_endpoint(
        (
            args.url.as_ref(),
            SecurityPolicy::None.to_str(),
            MessageSecurityMode::None,
            UserTokenPolicy::anonymous(),
        ),
        IdentityToken::Anonymous,
    ).unwrap();
    println!("Connected");

    let root_id = ObjectId::ObjectsFolder.into();
    let root = BrowseDescription {
        node_id: root_id,
        browse_direction: BrowseDirection::Forward,
        reference_type_id: ReferenceTypeId::Organizes.into(),
        include_subtypes: true,
        node_class_mask: (NodeClassMask::OBJECT | NodeClassMask::VARIABLE).bits(),
        result_mask: 0b111111
    };

    let mut stack = vec![root];

    while let Some(next) = stack.pop() {

        let mut reader = session.write().unwrap();
        let res = reader.browse(&[next]).unwrap();
        if let Some(browse_results) = res {
            //println!(">>> Got browse_result with {} items", browse_results.len());
            for browse_result in browse_results {
                if let Some(references) = browse_result.references {
                    //println!(">>> browse_result has {} references", references.len());
                    for reference in references {
                        let node_id = reference.node_id.node_id.clone();
                        let name = reference.display_name.text;
                        let node_class = reference.node_class;

                        // Standard folder definition
                        let is_folder = reference.type_definition.node_id == ObjectTypeId::FolderType.into();

                        let browse_anyway = is_folder || reference.type_definition.node_id.namespace != 0 && node_class == NodeClass::Object;
                        let type_def = reference.type_definition;

                        let is_var = node_class == NodeClass::Variable;
                        let pre = if is_var { "VAR" } else { "DIR" };

                        if is_var {
                            let read_type = ReadValueId {
                                node_id: node_id.clone(),
                                attribute_id: AttributeId::DataType as u32,
                                index_range: UAString::null(),
                                data_encoding: QualifiedName::null(),
                            };
                            //print!(">>> VAR {} ({}) type_def: {} .... ", name, node_id, type_def);
                            let do_read = match reader.read(&[read_type], TimestampsToReturn::Neither, 21000.0) {
                                Ok(typs) => {
                                    let typ = &typs[0];
                                    let do_read = if let Some(v) = &typ.value {
                                        match v {
                                            Variant::NodeId(node_id) => match node_id.identifier {
                                                Identifier::Numeric(n) => n < 24,
                                                _ => false,
                                            }
                                            _ => false,
                                        }
                                    } else {
                                        false
                                    };
                                    //println!("{:?} do_read = {}", typs, do_read);
                                    do_read
                                }
                                Err(err) => {
                                    eprintln!("Error reading data type! {}", err);
                                    false
                                }
                            };
                            if do_read {
                                let read_value = ReadValueId {
                                    node_id: node_id.clone(),
                                    attribute_id: AttributeId::Value as u32,
                                    index_range: UAString::null(),
                                    data_encoding: QualifiedName::null(),
                                };
                                println!(">>> Reading value for {} ({}) t={}", name, node_id, type_def);
                                match reader.read(&[read_value], TimestampsToReturn::Neither, 21000.0) {
                                    Ok(vals) => println!(">>> {:?}", vals),
                                    Err(err) => eprintln!(">>> NOOOOOOOOOOOooooo...... {}", err)
                                }
                                println!("");
                            }
                        } else {
                            //println!(">>> {} {} ({}) type_def: {}, is_folder = {} browse_anyway = {}", pre, name, node_id, type_def, is_folder, browse_anyway);
                        }

                        if browse_anyway {
                            stack.push(BrowseDescription {
                                node_id,
                                browse_direction: BrowseDirection::Forward,
                                reference_type_id: ReferenceTypeId::Organizes.into(),
                                include_subtypes: true,
                                node_class_mask: 0b00000011,
                                result_mask: 0b111111
                            });
                        }

                        // TODO: If node_class == NodeClass::Variable, go read a sample
                        // Something like this:
                        //reader.read(&[
                        //    ReadValueId {
                        //        node_id: node_id.clone(),
                        //        attribute_id: AttributeId::Value as u32,
                        //        index_range: UAString::null(),
                        //        data_encoding: QualifiedName::null(),
                        //    }
                        //]);
                    }
                }
            }
        }
    }

    Ok(())
}

