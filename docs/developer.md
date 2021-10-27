# Debugging / Development information

This is just a loose list of things that can come in useful for debugging and development. This is on top of anything written in the [setup](./setup.md) documentation.

## Use latest stable Rust

OPCUA for Rust will always track quite close to the most stable version of Rust, therefore ensure your toolchain is kept up to date.

## Rustfmt

Rustfmt will be used to format the sources and ensure a consistent style. Install rustfmt like so:

```
rustup component add rustfmt
```

Ensure you run `cargo fmt` on any changes you make. e.g.

```
cd opcua
cargo fmt
```

## CLion

CLion has very good Rust support. Install the `rust` and `toml` plugins and choose to use them with your existing Rust toolchain.

1. Enable "Use rustfmt instead of built-in formatter"
2. Enable "Run rustfmt on save"

## Visual Studio Code

TODO

## OpenSSL

OpenSSL is the most painful build component so ensure you read [setup](./setup.md) for information.

It would be very nice if OpenSSL could be replaced by a native Rust crypto library but given the breadth of things we use, this seems unlikely in the short term. See [crypto](./crypto.md) for more info.

## Wireshark

This is a useful link to follow about setting up [Wireshark for OPC UA](https://opcconnect.opcfoundation.org/2017/02/analyzing-opc-ua-communications-with-wireshark/). This allows you to capture network traffic and see how clients and servers are talking to each other. Wireshark has an OPC UA filter that decodes the binary traffic and tells you what requests and responses were being sent.

The only thing to add to the article is that most of the samples run on port 4855, so you should edit the settings for OPC UA and add port `4855` so that when you capture traffic and filter on `opcua` you see the port.