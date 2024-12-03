use std::{io::Write, net::TcpStream, time::Instant};

use ndarray_npy::write_npy;
use netsim::simulator::{run, Endpoint};
use pqsign::tls::{plain::PlainTls, pqc::PqcTls, pqccache::PqcWithCachingTls, Tls};
use ndarray::Array2;

fn test_tls<T: Tls>() -> Array2<f64> {
    let (mut cx, mut sx) = T::new();

    let mut e1: Endpoint = Box::new(|stream: &mut TcpStream| {
        T::client_transcript(&mut cx, stream);
        stream.flush().unwrap();
        // println!("Client: sent transcript");
        let verified = T::client_verify(&mut cx, stream);
        // println!("Client: verify result is {verified}");
        if !verified {
            println!("Error: failed to verify!");
        }
    });

    let mut e2: Endpoint = Box::new(|stream: &mut TcpStream| {
        T::server_certificate(&mut sx, stream);
        // println!("Server: sent certificate chain");
        stream.flush().unwrap();
        T::server_certificate_verify(&mut sx, stream);
        // println!("Server: sent certificate verify");
        stream.flush().unwrap();
    });

    run((100..2100).step_by(100), (0..200).step_by(10), 10, &mut e1, &mut e2)
}

fn main() {
    let now = Instant::now();
    let arr = test_tls::<PlainTls>();
    println!("Plain tls done: {} s", now.elapsed().as_secs_f64());
    write_npy("out/plain-tls.npy", &arr).unwrap();
    let now = Instant::now();
    let arr = test_tls::<PqcTls>();
    println!("Pqc tls done: {} s", now.elapsed().as_secs_f64());
    write_npy("out/pqc-tls.npy", &arr).unwrap();
    let now = Instant::now();
    let arr = test_tls::<PqcWithCachingTls>();
    println!("Pqc with caching tls done: {} s", now.elapsed().as_secs_f64());
    write_npy("out/pqc-with-caching.npy", &arr).unwrap();
}
