use std::net::TcpStream;

use crate::{
    falcon::{Degree, Falcon},
    signing_scheme::{SigningScheme, ToBytes},
};

use super::{read_bytes_stream, write_bytes_stream, SignedCertificate, Tls};

pub struct PqcTls;

pub struct ClientCtx {
    falcon: Falcon,
    pk_root: Vec<u8>,
    sk_root: Vec<u8>,
}

pub struct ServerCtx {
    falcon: Falcon,
    cert_chain: Vec<SignedCertificate>,
    sk_end: Vec<u8>,
}

impl Tls for PqcTls {
    type CX = ClientCtx;
    type SX = ServerCtx;
    type S = Falcon;

    fn new() -> (ClientCtx, ServerCtx) {
        let (cert_chain, pk_root, sk_root, sk_end) = Self::make_cert_chain();

        let falcon1 = Falcon::new(Degree::F512, Some("seed1".as_bytes()));
        let falcon2 = Falcon::new(Degree::F512, Some("seed2".as_bytes()));

        (
            ClientCtx {
                falcon: falcon1,
                pk_root,
                sk_root,
            },
            ServerCtx {
                falcon: falcon2,
                cert_chain,
                sk_end,
            },
        )
    }

    fn make_cert_chain() -> (
        Vec<SignedCertificate>,
        <Self::S as SigningScheme>::VerifyingKey,
        <Self::S as SigningScheme>::SigningKey,
        <Self::S as SigningScheme>::SigningKey,
    ) {
        Self::_make_cert_chain(&mut Falcon::new(Degree::F512, Some("seed".as_bytes())))
    }

    fn client_transcript(_: &mut Self::CX, stream: &mut TcpStream) {
        write_bytes_stream(stream, "transcript-hash".as_bytes()).unwrap();
    }

    fn server_certificate(ctx: &mut Self::SX, stream: &mut TcpStream) {
        for cert in &ctx.cert_chain {
            let bytes = cert.to_bytes();
            write_bytes_stream(stream, &bytes).unwrap();
        }
    }

    fn server_certificate_verify(ctx: &mut Self::SX, stream: &mut TcpStream) {
        let mut transcript_bytes = read_bytes_stream(stream, "server_certificate_verify");
        transcript_bytes.extend(ctx.cert_chain.iter().flat_map(|cert| cert.to_bytes()));
        let signature = ctx.falcon.sign(&ctx.sk_end, &transcript_bytes);
        write_bytes_stream(stream, &signature.to_bytes()).unwrap();
    }

    fn client_verify(ctx: &mut Self::CX, stream: &mut TcpStream) -> bool {
        let mut certificate_chain: Vec<SignedCertificate> = Vec::new();

        for i in 0..3 {
            let cert: SignedCertificate =
                read_bytes_stream(stream, &format!("client_verify_cert_{i}")).into();
            certificate_chain.push(cert.clone());
            // println!("[client_verify] Received certificate {i}");
        }

        // Verify root cert is signed by pk_root

        let status = ctx.falcon.verify(
            &ctx.pk_root,
            &certificate_chain[2].certificate.to_bytes(),
            &certificate_chain[2].signature.clone().into(),
        );

        if !status {
            println!("[client_verify] Root cert verification failed");

            let _expected_sig = certificate_chain[2]
                .certificate
                .clone()
                .sign(&mut ctx.falcon, &ctx.sk_root)
                .signature;

            println!("[client_verify] Expected signature {_expected_sig:?}");
            return false;
        }

        // Verify transcript is signed correctly

        let certificate_verify = read_bytes_stream(stream, "client_verify_cert_verify");

        let mut m: Vec<u8> = "transcript-hash".into();
        m.extend(certificate_chain.iter().flat_map(|cert| cert.to_bytes()));

        let status = ctx.falcon.verify(
            &certificate_chain[0].certificate.subject_pk.clone().into(),
            &m,
            &certificate_verify.into(),
        );

        if !status {
            println!("[client_verify] certificate verify check failed");
        }

        status
    }
}
