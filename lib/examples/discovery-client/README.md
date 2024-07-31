This sample attempts to connect to a discovery server url and find servers from it.

Run the sample via `cargo run --example discovery-client` and it will attempt to connect to `opc.tcp://localhost:4840/`
and query the endpoints it finds.

If you want to query another discovery server, then pass the url on the command line like so
`cargo run --example discovery-client  -- --url opc.tcp://foo:4840/`.
