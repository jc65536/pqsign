use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pqsign::{
    eddsa::Eddsa,
    falcon::{Degree, Falcon},
    signing_scheme::SigningScheme,
};

fn bench_scheme<S: SigningScheme>(c: &mut Criterion, mut scheme: S) {
    c.bench_function("keygen", |b| b.iter(|| scheme.keygen()));

    let (sk, pk) = scheme.keygen();
    let m = "Hello World!";

    c.bench_with_input(BenchmarkId::new("sign", m), &(&sk, m), |b, &(sk, m)| {
        b.iter(|| scheme.sign(sk, m.as_bytes()))
    });

    let t = scheme.sign(&sk, m.as_bytes());

    c.bench_with_input(
        BenchmarkId::new("verify", m),
        &(&pk, m, &t),
        |b, &(pk, m, t)| b.iter(|| scheme.verify(pk, m.as_bytes(), t)),
    );
}

fn bench_eddsa(c: &mut Criterion) {
    bench_scheme(c, Eddsa);
}

fn bench_falcon(c: &mut Criterion) {
    bench_scheme(c, Falcon::new(Degree::F512, Some("seed".as_bytes())));
}

criterion_group!(bench_all, bench_eddsa, bench_falcon);
criterion_main!(bench_all);
