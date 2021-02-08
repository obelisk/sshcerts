use criterion::{criterion_group, criterion_main, Criterion};

use sshcerts::yubikey::{
    provision,
    RetiredSlotId,
    SlotId,
    ssh::{
        convert_to_ssh_pubkey,
        ssh_cert_signer,
        ssh_cert_fetch_pubkey,
    }
};

fn generate_certs(n: u64) -> () {
    let data = [0; 32];
    for _ in 0..n {
        ssh_cert_signer(&data, SlotId::Retired(RetiredSlotId::R20));
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("generate 3 signatures", |b| b.iter(|| generate_certs(3)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);