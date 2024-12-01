use std::net::TcpStream;

use crate::{
    eddsa::Eddsa,
    signing_scheme::{SigningScheme, ToBytes},
};

use super::{read_bytes_stream, write_bytes_stream, SignedCertificate, Tls};

pub struct PlainTls;

pub struct ClientCtx {
    pk_root: <Eddsa as SigningScheme>::VerifyingKey,
    sk_root: <Eddsa as SigningScheme>::SigningKey,
}

pub struct ServerCtx {
    cert_chain: Vec<SignedCertificate>,
    sk_end: <Eddsa as SigningScheme>::SigningKey,
}

impl PlainTls {
    pub fn new() -> (ClientCtx, ServerCtx) {
        let (cert_chain, pk_root, sk_root, sk_end) = Self::make_cert_chain();

        (
            ClientCtx { pk_root, sk_root },
            ServerCtx { cert_chain, sk_end },
        )
    }
}

impl Tls for PlainTls {
    type CX = ClientCtx;
    type SX = ServerCtx;
    type S = Eddsa;

    fn make_cert_chain() -> (
        Vec<SignedCertificate>,
        <Self::S as SigningScheme>::VerifyingKey,
        <Self::S as SigningScheme>::SigningKey,
        <Self::S as SigningScheme>::SigningKey,
    ) {
        Self::_make_cert_chain(&mut Eddsa)
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
        let signature = Eddsa.sign(&ctx.sk_end, &transcript_bytes);
        write_bytes_stream(stream, &signature.to_bytes()).unwrap();
    }

    fn client_verify(ctx: &mut Self::CX, stream: &mut TcpStream) -> bool {
        let mut certificate_chain: Vec<SignedCertificate> = Vec::new();

        for i in 0..3 {
            let cert: SignedCertificate =
                read_bytes_stream(stream, &format!("client_verify_cert_{i}")).into();
            certificate_chain.push(cert.clone());
            println!("[client_verify] Received certificate {:?}", cert);
        }

        // Verify root cert is signed by pk_root

        let status = Eddsa.verify(
            &ctx.pk_root,
            &certificate_chain[2].certificate.to_bytes(),
            &certificate_chain[2].signature.clone().into(),
        );

        if !status {
            println!("[client_verify] Root cert verification failed");

            let expected_sig = certificate_chain[2]
                .certificate
                .clone()
                .sign(&mut Eddsa, &ctx.sk_root)
                .signature;

            println!("[client_verify] Expected signature {expected_sig:?}");
            return false;
        }

        // Verify transcript is signed correctly

        let certificate_verify = read_bytes_stream(stream, "client_verify_cert_verify");

        let mut m: Vec<u8> = "transcript-hash".into();
        m.extend(certificate_chain.iter().flat_map(|cert| cert.to_bytes()));

        let status = Eddsa.verify(
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
