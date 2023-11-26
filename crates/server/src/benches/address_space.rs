#[macro_use]
extern crate criterion;

use criterion::Criterion;

use crate::server::address_space::{address_space::AddressSpace, references::References};
use crate::types::node_ids::ReferenceTypeId;

fn populate_address_space() {
    let _address_space = AddressSpace::new();
}

fn address_space_benchmark(c: &mut Criterion) {
    // This benchmark tests how long it takes to populate the address space
    c.bench_function("address_space", |b| b.iter(|| populate_address_space()));
}

fn reference_type_matches(references: &References) {
    let r1 = ReferenceTypeId::References.into();
    let r2 = ReferenceTypeId::AlwaysGeneratesEvent.into();
    let r3 = ReferenceTypeId::HierarchicalReferences.into();
    // AlwaysGeneratesEvent is a subtype of References via NonHierarchicalReferences
    assert!(references.reference_type_matches(&r1, &r2, true));
    // AlwaysGeneratesEvent is not a subtype of HierarchicalReferences
    assert!(!references.reference_type_matches(&r3, &r2, true));
}

fn reference_type_benchmark(c: &mut Criterion) {
    // This bench mark test how long it takes to test if one reference type is a subtype of another
    c.bench_function("reference_type_benchmark", |b| {
        let address_space = AddressSpace::new();
        let references = address_space.references();
        b.iter(|| reference_type_matches(references));
    });
}

criterion_group!(benches, address_space_benchmark, reference_type_benchmark);
criterion_main!(benches);
