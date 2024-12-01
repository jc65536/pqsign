use std::net::TcpStream;

use netsim::simulator::{run_once, Endpoint};
use pqsign::tls::{plain::PlainTls, pqc::PqcTls, pqccache::PqcWithCachingTls, Tls};

fn main() {
    let (mut cx, mut sx) = PqcWithCachingTls::new();

    let mut e1: Endpoint = Box::new(|stream: &mut TcpStream| {
        PqcWithCachingTls::client_transcript(&mut cx, stream);
        println!("Client: sent transcript");
        let verified = PqcWithCachingTls::client_verify(&mut cx, stream);
        println!("Client: verify result is {verified}");
    });

    let mut e2: Endpoint = Box::new(|stream: &mut TcpStream| {
        PqcWithCachingTls::server_certificate(&mut sx, stream);
        println!("Server: sent certificate chain");
        PqcWithCachingTls::server_certificate_verify(&mut sx, stream);
        println!("Server: sent certificate verify");
    });

    run_once(500, 100, 3, &mut e1, &mut e2);
}
