# MODBUS to OPC UA server

This is a simple server that reads coils and registers from a MODBUS slave and exposes them as variables in OPC UA.

MODBUS exposes registers (2-bytes) and coils (discrete on/off values, i.e. bools) which are input (read-only)
or output (read-write). Each is addressable and and occupy one of 4 tables:

* 0xxxx - Discrete Output Coil from 1 to 9999 - Read-Write
* 1xxxx - Discrete Input Coil from 10001 to 19999 - Read-Only
* 3xxxx - Input Register from 30001 to 39999 - Read-Only - **UTILISED**
* 4xxxx - Output Holding Register from 40001 to 49999 - Read-Write

Within each table, each data is addressed 0-9998 or 0000-270E in hex.

Only the tables marked UTILISED are used by this demo. In MODBUS the
the master is expected to know what they are requesting and the meaning
of each value returned, e.g. if input register 10001 reports the temperature
of a device, then the master is expected to know that because there is 
no metadata describing it's purpose.

That brings us onto how then we represent MODBUS as OPC UA. There
are basically two main ways:

1. The OPC UA server has some kind of naming map where register X becomes variable Foo. The server could even 
map adjacent registers into 32-bit and 64-bit values providing byte order and endianess were defined. 

2. The OPC UA server generically exposes each register / coils in an addressable fashion and leaves it up to
 the OPC UA client to make sense of the meaning of each value.

The sample will do option 2) for the time being because it is a little simpler, however it is not hard
to see how option 1 could _also_ be supported and perhaps may eventually happen.

## Address space

This sample exposes registers / coils into the address space like this.

```
Objects/
  MODBUS/
    Input Coils
      Input Coil 0
      ...
      Input Coil N - 1
    Input Registers/
      Input Register 0
      ...
      Input Register N - 1
```

Where `Input Register 0` is the first register in the table up to a count of N registers configured
when the server was started. Registers are of type `UInt16` and coils are of type `Boolean`.
 
If the server is configured to reads registers / coils from a non-zero base address, indexing
will happen with whatever address was specified, e.g. if the base address for input registers was 1000 then
variables will be called `Input Register 1000`, `Input Register 1001` etc.

## Demo MODBUS server

To simplify testing, the demo takes a `--run-demo-slave` argument. If this flag is given the
server will launch its own MODBUS slave on a thread. The demo slave contains some changing and static
values to observe the behaviour of the OPC UA.

```bash
cd samples/modbus-server
cargo run -- --run-demo-slave
```

## Configuration file

The sample reads a `modbus.conf` which defines its configuration. 

The default configuration can be overridden by providing an alternative path via a `--config filename` option, e.g.

```bash
cargo run -- --config ../mymodbus.conf
```

The configuration defines which coils and registers to read. For example:

```

---
slave_address: "127.0.0.1:502"
read_interval: 1000
output_coil_base_address: 0
output_coil_count: 0
input_coil_base_address: 0
input_coil_count: 20
input_register_base_address: 0
input_register_count: 9
output_register_base_address: 0
output_register_count: 0
```

* The `slave_address` which is IP address of the slave device that it will connect to.
* The `read_interval` is the duration in milliseconds that values are polled from the slave.
* There is a `base_address` and a `count` for each table, e.g. `input_coil_base_address` and `input_coil_count`. The
 base address is the starting address to read values from and the count is the number of consecutive values to read.

