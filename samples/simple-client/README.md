To run this sample:

1. Launch either the `lib/examples/simple-server`, or `3rd-party/node-opcua-server`. Both servers expose the same variables. 
2. Run as `cargo run`

The client connects to the server, creates a subscription to variables v1, 
v2, v3, v4 and continues to print out changes to those values without terminating.

## Crypto

At startup the client will check for, and if necessary create a `pki/` folder. It will create a certificate
for itself if one does not exist already. When the client connects to a server over a signed or signed/encrypted
connection it will present this server. Servers can reject certs they do not recognise so you may have to
manually add trust for your client before it will work - this really depends on how your server functions.

The client's `client.conf` is set up to automatically trust the server's certificate so you do not need to do anything
special client side.
