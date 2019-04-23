#[macro_use]
extern crate criterion;

use criterion::Criterion;

use opcua_server::address_space::AddressSpace;

fn populate_address_space() {
    let _address_space = AddressSpace::new();
}

fn address_space_benchmark(c: &mut Criterion) {
    c.bench_function("address_space", |b| b.iter(|| populate_address_space()));
}

criterion_group!(benches, address_space_benchmark);
criterion_main!(benches);