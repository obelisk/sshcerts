use criterion::{criterion_group, criterion_main, Criterion};
use sshcerts::yubikey::piv::Yubikey;
use yubikey::piv::{RetiredSlotId, SlotId};

fn generate_certs(n: u64) -> () {
    let data = [0; 32];
    let mut yk = Yubikey::new().unwrap();
    for _ in 0..n {
        yk.ssh_cert_signer(&data, &SlotId::Retired(RetiredSlotId::R19))
            .unwrap();
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("generate 3 signatures", |b| b.iter(|| generate_certs(5)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
