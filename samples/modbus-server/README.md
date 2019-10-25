# MODBUS to OPC UA server

This is a simple server that reads coils and registers from a MODBUS slave and exposes them as variables in OPC UA.

MODBUS exposes registers (2-bytes) and coils (discrete on/off values, i.e. bools) which are input (read-only)
or output (read-write). 

Each is addressable by a number and and occupies one of 4 tables.

* Number 0xxxx - Discrete Output Coil from 1 to 9999 - Read-Write
* Number 1xxxx - Discrete Input Coil from 10001 to 19999 - Read-Only
* Number 3xxxx - Input Register from 30001 to 39999 - Read-Only
* Number 4xxxx - Output Holding Register from 40001 to 49999 - Read-Write

Within each table, each data is addressed 0-9998 or 0000-270E in hex. So addressing an input coil would be
10001 + address, so 10001 + 0, up to 19999 (10001 + 9998). Basically the numbers are 1-indexed but the addresses
are 0-indexed. Yes it's weird. 

In MODBUS the the master is expected to know what they are requesting and the meaning of each value returned, e.g. if
input register 10001 reports the temperature of a device, then the master is expected to know that because there is no
metadata describing it's purpose. 

This server is controlled by a configuration file that allows you to define "aliases" to impart meaning onto registers
and coils.

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
aliases:
  - name: "Pump #1 Power"
    number: 10001
  - name: "Temperature"
    number: 30001
    data_type: Int32
```

* The `slave_address` which is IP address of the slave device that it will connect to.
* The `read_interval` is the duration in milliseconds that values are polled from the slave.
* There is a `base_address` and a `count` for each table, e.g. `input_coil_base_address` and `input_coil_count`. The
 base address is the starting address to read values from and the count is the number of consecutive values to read.


### Aliases

You can also define an alias for a coil or register(s). Aliases appear in a separate folder of the address space under 
`Objects/MODBUS/Aliases`.

Each alias consists of a:

1. `name` - An alpha numeric name which must be unique from other aliases
2. `number` - the number of the register / coil, i.e. 0-9999, 10001-19999, 30001-39999, 40001-49999. The number MUST resolve to a
value being captured, i.e. you cannot specify a number which lies outside the base address / count defined for that table.
3. `data_type` - optional. For register types ONLY. The type coerces the value in the register(s) to another type. The default type is UInt16.

Aliasing will attempt to use bitwise conversions to preserve the original value for some types and casting / coercion 
for others. Refer to this list to see which applies.

* Boolean - 1 register. A register with a value of 0 becomes `false`, otherwise `true`. 
* Byte - 1 register. Value is clamped 0 to 255, i.e. if the value is > 255, it reports as 255
* SByte - 1 register bytes treated as a signed 16-bit integer is clamped -127 to 128, i.e. if the value < -127 or > 128 it reports as one of those limits else the real value.
* UInt16 - 1 register. This is the default register format.
* Int16 - 1 register. A bitwise conversion of the word, treated as a signed integer.
* UInt32 - A bitwise conversion of 2 consecutive registers. Affected by endianness.
* Int32 - A bitwise conversion of 2 consecutive registers. Affected by endianness.
* UInt64 - A bitwise conversion of 4 consecutive registers. Affected by endianness.
* Int64 - A bitwise conversion of 4 consecutive registers. Affected by endianness.
* Float - A bitwise conversion of 2 consecutive registers. Affected by endianness.
* Double - A bitwise conversion of 4 consecutive registers. Affected by endianness.

If a type uses consecutive registers then the endianness rules are used to resolved the value. 

It is an error to alias register numbers, or required consecutive numbers outside of the requested range.

```
#...
aliases:
  - name: "Pump #1 Power"
    number: 10001
  - name: "Temperature"
    number: 30001
    data_type: Int32
```

### Endianness rules

Endianness is a potential head wrecker, so this implementation takes a relatively simple approach:

1. The MODBUS slave is assumed to return word values big-endian, as per spec.
2. The MODBUS slave is assumed to return consecutive values for 32-bit or 64-bit values types that are also big-endian,
 e.g. the number 64-bit number `0x0102030405060708` will be in consecutive register words like so `[0x0102],[0x0304],[0x0506],[0x0708]`.
3. For 32-bit and 64-bit floating point types, the format is assumed to be consecutive big endian bytes which are bitwise
converted to their float equivalents. 
 
In other words, this sample assumes a sane MODBUS slave. It may be that there are broken MODBUS slaves out there which mangle
the ordering of words, or double words which require some flipping, but this implementation will not second guess
that behaviour for the time being.

## Address Space representation

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
    Aliases/
      Pump #1 Power
      Temperature
      ...
```

Where `Input Register 0` is the first register in the table up to a count of N registers configured
when the server was started. Registers are of type `UInt16` and coils are of type `Boolean`.
 
If the server is configured to reads registers / coils from a non-zero base address, indexing
will happen with whatever address was specified, e.g. if the base address for input registers was 1000 then
variables will be called `Input Register 1000`, `Input Register 1001` etc.

Any defined aliases are described in the `Aliases` section as they were set in the configuration file. 

## Demo MODBUS server

To simplify testing, the demo takes a `--run-demo-slave` argument. If this flag is given the
server will launch its own MODBUS slave on a thread. The demo slave contains some changing and static
values to observe the behaviour of the OPC UA.

```bash
cd samples/modbus-server
cargo run -- --run-demo-slave
```
