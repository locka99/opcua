A simple server that reads coils and registers from a MODBUS slave and exposes them as variables in OPC UA.

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

1. The OPC UA server has a map describing the purpose and type of each
register / coil and performs the mapping and transformation.

2. The OPC UA server is more generic and exposes each register / coils in an addressable fashion and leaves it up to
 the OPC UA client to make sense of the meaning of each value.

This sample exposes them like this.

```
Objects/
  MODBUS/
    Input Coils
      Coil 0
      ...
      Coil N - 1
    Input Registers/
      Register 0
      ...
      Register N - 1
```

Where Input Register 0 is the first register in the requested range up to N registers requested
when the server was started.

To simplify testing, the demo takes a `--run-demo-slave` argument. If this flag is given the
server will launch its own MODBUS slave on one thread and connect to it from another.

```
cd samples/modbus-server
cargo run -- --run-demo-slave
```

Otherwise supply a `--slave-address host:port` argument to tell it which MODBUS slave to connect with.

```
cd samples/modbus-server
cargo run -- --slave-address 192.168.1.100:5504
```

The sample also takes arguments to control which input registers to show:
 
* `--input-register-address N` where N is the address of the first input register to map
* `--input-register-quantity N` where N is the number of registers to expose through OPC UA starting from the address and incrementing.
