use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pqsign::{eddsa::Eddsa, signing_scheme::SigningScheme};

fn bench_scheme<S: SigningScheme>(c: &mut Criterion) {
    c.bench_function("keygen", |b| b.iter(|| S::keygen()));

    let (sk, pk) = S::keygen();
    let m = "Hello World!";

    c.bench_with_input(BenchmarkId::new("sign", m), &(&sk, m), |b, &(sk, m)| {
        b.iter(|| S::sign(sk, m))
    });

    let t = S::sign(&sk, m);

    c.bench_with_input(
        BenchmarkId::new("verify", m),
        &(&pk, m, &t),
        |b, &(pk, m, t)| b.iter(|| S::verify(pk, m, t)),
    );
}

criterion_group!(bench_all, bench_scheme<Eddsa>);
criterion_main!(bench_all);
