A very simple server that reads registers from a MODBUS simulator and exposes them as variables in OPC UA.

It is tested using a simple [MODBUS simulator](https://github.com/taka-wang/c-modbus-slave) which in turn depends on
 [libmodbus](https://libmodbus.org/download/). NOTE: The simulator is probably too simple since the values do not change.
 
Build and install libmodbus and then run the simulator:

```bash
cd c-modbus-slave/src
gcc server.c -o server -Wall -std=c99 `pkg-config --libs --cflags libmodbus`
./server
```

In OPC UA Rust:

```bash
cd samples/modbus-server
cargo run
```

In a OPC UA client, browse for `MODBUS/Input Register 0` etc.
