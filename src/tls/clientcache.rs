use std::{collections::HashMap, net::TcpStream};

use crate::{
    falcon::{Degree, Falcon},
    signing_scheme::{SigningScheme, ToBytes},
};

use super::{read_bytes_stream, write_bytes_stream, Certificate, SignedCertificate, Tls};

pub struct ClientCachingTls;

pub struct ClientCtx {
    falcon: Falcon,
    pk_root: Vec<u8>,
    pk_self: Vec<u8>,
    sk_self: Vec<u8>,
    pk_server: Option<Vec<u8>>,
}

pub struct ServerCtx {
    falcon: Falcon,
    cert_chain: Vec<SignedCertificate>,
    sk_end: Vec<u8>,
    first: bool,
}

impl Tls for ClientCachingTls {
    type CX = ClientCtx;
    type SX = ServerCtx;
    type S = Falcon;

    fn new() -> (ClientCtx, ServerCtx) {
        let (cert_chain, pk_root, _, sk_end) = Self::make_cert_chain();

        let mut falcon1 = Falcon::new(Degree::F512, Some("seed1".as_bytes()));

        let (sk_self, pk_self) = falcon1.keygen();

        let falcon2 = Falcon::new(Degree::F512, Some("seed2".as_bytes()));

        (
            ClientCtx {
                falcon: falcon1,
                pk_root,
                pk_self,
                sk_self,
                pk_server: None,
            },
            ServerCtx {
                falcon: falcon2,
                cert_chain,
                sk_end,
                first: true,
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

    fn client_transcript(ctx: &mut Self::CX, stream: &mut TcpStream) {
        if ctx.pk_server.is_none() {
            write_bytes_stream(stream, "first".as_bytes()).unwrap();
        } else {
            write_bytes_stream(stream, "repeat".as_bytes()).unwrap();
        }

        write_bytes_stream(stream, "transcript-hash".as_bytes()).unwrap();
    }

    fn server_certificate(ctx: &mut Self::SX, stream: &mut TcpStream) {
        let msg =
            String::from_utf8(read_bytes_stream(stream, "server_certificate_det_first")).unwrap();

        match msg.as_str() {
            "first" => ctx.first = true,
            "repeat" => ctx.first = false,
            x => panic!("Didn't get first or repeat, got {x} instead"),
        }

        if ctx.first {
            for cert in &ctx.cert_chain {
                let bytes = cert.to_bytes();
                write_bytes_stream(stream, &bytes).unwrap();
            }
        }
    }

    fn server_certificate_verify(ctx: &mut Self::SX, stream: &mut TcpStream) {
        let mut transcript_bytes =
            read_bytes_stream(stream, "server_certificate_verify_transcript");

        if ctx.first {
            transcript_bytes.extend(ctx.cert_chain.iter().flat_map(|cert| cert.to_bytes()));
        }

        let signature = ctx.falcon.sign(&ctx.sk_end, &transcript_bytes);
        write_bytes_stream(stream, &signature.to_bytes()).unwrap();
    }

    fn client_verify(ctx: &mut Self::CX, stream: &mut TcpStream) -> bool {
        let mut certificate_chain: Vec<SignedCertificate> = Vec::new();

        if ctx.pk_server.is_none() {
            for i in 0..3 {
                let cert: SignedCertificate =
                    read_bytes_stream(stream, &format!("client_verify_cert_{i}")).into();
                certificate_chain.push(cert.clone());
                // println!("[client_verify] Received certificate {i}");
            }

            // Verify root cert is signed by pk_root

            let status = ctx.falcon.verify(
                &ctx.pk_root,
                &certificate_chain.last().unwrap().certificate.to_bytes(),
                &certificate_chain.last().unwrap().signature.clone().into(),
            );

            if !status {
                println!("[client_verify] Root cert verification failed");
                return false;
            }

            ctx.pk_server = Some(certificate_chain[0].certificate.subject_pk.clone())
        }

        // Verify transcript is signed correctly

        let certificate_verify = read_bytes_stream(stream, "client_verify_cert_verify");

        let mut m: Vec<u8> = "transcript-hash".into();
        m.extend(certificate_chain.iter().flat_map(|cert| cert.to_bytes()));

        let status = ctx.falcon.verify(
            ctx.pk_server
                .as_ref()
                .unwrap_or_else(|| &certificate_chain[0].certificate.subject_pk),
            &m,
            &certificate_verify.into(),
        );

        if !status {
            println!("[client_verify] certificate verify check failed");
            return false;
        }

        true
    }
}
