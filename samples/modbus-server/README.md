A simple server that reads registers from a MODBUS slave and exposes them as variables in OPC UA.

MODBUS basically consists of registers (2-byte words) and coils (flags) which occupy one of 4 tables with an addressable
index as follows:

* 0xxxx - Status Coil Address Space from 00000 to 065535
* 1xxxx - Input Coil Address Space from 10000 to 165535
* 3xxxx - Input Register Address Space from 30000 to 365535 - UTILISED
* 4xxxx - Holding Register Address Space from 40000 to 465535

Only the tables marked UTILISED are used by this demo.

The address space is numerically indexed and the caller (called the master) is expected to know what they are requesting
and what that value represents.

MODBUS could be represented in a number of ways through OPC UA address space. This
sample exposes them like this.

```
Objects/
  MODBUS/
    Input Register 0
    Input Register 1
    ...
    Input Register N - 1
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
