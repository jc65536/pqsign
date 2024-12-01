use std::{collections::HashMap, net::TcpStream};

use crate::{
    falcon::{Degree, Falcon},
    signing_scheme::{SigningScheme, ToBytes},
};

use super::{read_bytes_stream, write_bytes_stream, Certificate, SignedCertificate, Tls};

pub struct PqcWithCachingTls;

pub struct ClientCtx {
    falcon: Falcon,
    pk_root: Vec<u8>,
    pk_self: Vec<u8>,
    sk_self: Vec<u8>,
    first: bool,
    id: u32,
}

pub struct ServerCtx {
    falcon: Falcon,
    cert_chain: Vec<SignedCertificate>,
    sk_end: Vec<u8>,
    cache: HashMap<u32, SignedCertificate>,
    first: bool,
    id: u32,
}

impl PqcWithCachingTls {
    pub fn new() -> (ClientCtx, ServerCtx) {
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
                first: true,
                id: 1,
            },
            ServerCtx {
                falcon: falcon2,
                cert_chain,
                sk_end,
                cache: HashMap::new(),
                first: true,
                id: 0,
            },
        )
    }
}

impl Tls for PqcWithCachingTls {
    type CX = ClientCtx;
    type SX = ServerCtx;
    type S = Falcon;

    fn make_cert_chain() -> (
        Vec<SignedCertificate>,
        <Self::S as SigningScheme>::VerifyingKey,
        <Self::S as SigningScheme>::SigningKey,
        <Self::S as SigningScheme>::SigningKey,
    ) {
        Self::_make_cert_chain(&mut Falcon::new(Degree::F512, Some("seed".as_bytes())))
    }

    fn client_transcript(ctx: &mut Self::CX, stream: &mut TcpStream) {
        if ctx.first {
            write_bytes_stream(stream, format!("first {}", ctx.id).as_bytes()).unwrap();
        } else {
            write_bytes_stream(stream, format!("repeat {}", ctx.id).as_bytes()).unwrap();
        }

        write_bytes_stream(stream, "transcript-hash".as_bytes()).unwrap();
    }

    fn server_certificate(ctx: &mut Self::SX, stream: &mut TcpStream) {
        let msg =
            String::from_utf8(read_bytes_stream(stream, "server_certificate_det_first")).unwrap();
        let msg: Vec<&str> = msg.split(" ").collect();

        ctx.id = msg[1].parse().unwrap();

        match msg[0] {
            "first" => ctx.first = true,
            "repeat" => ctx.first = false,
            x => panic!("Didn't get first or repeat, got {x} instead"),
        }

        if ctx.first {
            for cert in &ctx.cert_chain {
                let bytes = cert.to_bytes();
                write_bytes_stream(stream, &bytes).unwrap();
            }
        } else {
            let bytes = ctx.cache.get(&ctx.id).unwrap().to_bytes();
            write_bytes_stream(stream, &bytes).unwrap();
        }
    }

    fn server_certificate_verify(ctx: &mut Self::SX, stream: &mut TcpStream) {
        let mut transcript_bytes =
            read_bytes_stream(stream, "server_certificate_verify_transcript");

        if ctx.first {
            transcript_bytes.extend(ctx.cert_chain.iter().flat_map(|cert| cert.to_bytes()));
        } else {
            transcript_bytes.extend(ctx.cache.get(&ctx.id).unwrap().to_bytes());
        }

        let signature = ctx.falcon.sign(&ctx.sk_end, &transcript_bytes);
        write_bytes_stream(stream, &signature.to_bytes()).unwrap();

        if ctx.first {
            let client_cert_bytes =
                read_bytes_stream(stream, "server_certificate_verify_client_cert");
            let client_cert: SignedCertificate = client_cert_bytes.into();
            ctx.cache.insert(ctx.id, client_cert);
        }
    }

    fn client_verify(ctx: &mut Self::CX, stream: &mut TcpStream) -> bool {
        let mut certificate_chain: Vec<SignedCertificate> = Vec::new();

        for i in 0..(if ctx.first { 3 } else { 1 }) {
            let cert: SignedCertificate =
                read_bytes_stream(stream, &format!("client_verify_cert_{i}")).into();
            certificate_chain.push(cert.clone());
            println!("[client_verify] Received certificate {:?}", cert);
        }

        // Verify root cert is signed by pk_root

        let status = ctx.falcon.verify(
            if ctx.first {
                &ctx.pk_root
            } else {
                &ctx.pk_self
            },
            &certificate_chain.last().unwrap().certificate.to_bytes(),
            &certificate_chain.last().unwrap().signature.clone().into(),
        );

        if !status {
            println!("[client_verify] Root cert verification failed");
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
            return false;
        }

        if ctx.first {
            let cert = Certificate {
                issuer_name: "client".to_string(),
                subject_name: "end-entity".to_string(),
                subject_pk: certificate_chain[0].certificate.subject_pk.clone(),
            }
            .sign(&mut ctx.falcon, &ctx.sk_self);

            let cert_bytes = cert.to_bytes();

            write_bytes_stream(stream, &cert_bytes).unwrap();

            ctx.first = false;
        }

        true
    }
}
