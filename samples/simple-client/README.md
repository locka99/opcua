To run this sample:

1. Launch either the `samples/simple-server`, or `3rd-party/node-opcua-server`. Both servers expose the same variables. 
2. a) `cargo run`, or b) `cargo run -- --subscribe`

Without an argument the client will connect to the server, read and print out the current values of v1, v2, v3 v4 and terminate. 

With the `--subscribe` argument the client will connect to the server, create a subscription and monitor changes on v1, 
v2, v3, v4 and continue to print out changes without terminating.

## Crypto

At startup the client will check for, and if necessary create a `pki/` folder. It will create a certificate
for itself if one does not exist already. When the client connects to a server over a signed or signed/encrypted
connection it will present this server. Servers can reject certs they do not recognise so you may have to
manually add trust for your client before it will work - this really depends on how your server functions.

The client's `client.conf` is set up to automatically trust the server's certificate so you do not need to do anything
special client side.
