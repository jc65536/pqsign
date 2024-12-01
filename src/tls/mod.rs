pub mod plain;
pub mod pqc;
pub mod pqccache;

use std::{
    io::{Read, Write},
    mem::size_of,
    net::TcpStream,
};

use crate::signing_scheme::{SigningScheme, ToBytes};

fn read_bytes(value: &Vec<u8>, mut start: usize) -> (&[u8], usize) {
    let len = usize::from_be_bytes(value[start..start + size_of::<usize>()].try_into().unwrap());
    start += size_of::<usize>();
    (&value[start..start + len], start + len)
}

fn read_bytes_stream(reader: &mut impl Read, dbg: &str) -> Vec<u8> {
    let mut len_bytes = [0; size_of::<usize>()];
    reader.read_exact(&mut len_bytes).unwrap();
    let len = usize::from_be_bytes(len_bytes);
    let mut buf = vec![0; len];
    reader.read_exact(&mut buf).unwrap();

    // match String::from_utf8(buf.clone()) {
    //     Ok(s) => println!("[{dbg}] read_bytes_stream ({}): \"{}\"", len, s),
    //     _ => println!("[{dbg}] read_bytes_stream ({len}): {buf:?}"),
    // }
    buf
}

fn write_bytes_stream(writer: &mut impl Write, data: &[u8]) -> std::io::Result<usize> {
    let mut n = writer.write(&data.len().to_be_bytes())?;
    n += writer.write(data)?;
    Ok(n)
}

#[derive(Debug, Clone)]
struct Certificate {
    issuer_name: String,
    subject_name: String,
    subject_pk: Vec<u8>,
}

impl Certificate {
    pub fn sign<S: SigningScheme>(self, scheme: &mut S, sk: &S::SigningKey) -> SignedCertificate {
        let signature = scheme.sign(sk, &self.to_bytes());

        SignedCertificate {
            certificate: self,
            signature: signature.to_bytes(),
        }
    }
}

impl ToBytes for Certificate {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();

        res.extend(self.issuer_name.len().to_be_bytes());
        res.extend(self.issuer_name.as_bytes());
        res.extend(self.subject_name.len().to_be_bytes());
        res.extend(self.subject_name.as_bytes());
        res.extend(self.subject_pk.len().to_be_bytes());
        res.extend(&self.subject_pk);

        res
    }
}

impl From<Vec<u8>> for Certificate {
    fn from(value: Vec<u8>) -> Self {
        let (t, start) = read_bytes(&value, 0);
        let issuer_name = String::from_utf8(t.into()).unwrap();
        let (t, start) = read_bytes(&value, start);
        let subject_name = String::from_utf8(t.into()).unwrap();
        let (t, _) = read_bytes(&value, start);
        let subject_pk = t.into();

        Self {
            issuer_name,
            subject_name,
            subject_pk,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedCertificate {
    certificate: Certificate,
    signature: Vec<u8>,
}

impl ToBytes for SignedCertificate {
    /**
     * Format
     * ------
     * [issuer_name len] issuer_name
     * [subject_name len] subject_name
     * ...
     * [signature len] signature
     */
    fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();

        let cert_bytes = self.certificate.to_bytes();

        res.extend(cert_bytes.len().to_be_bytes());
        res.extend(&cert_bytes);

        res.extend(self.signature.len().to_be_bytes());
        res.extend(&self.signature);

        res
    }
}

impl From<Vec<u8>> for SignedCertificate {
    fn from(value: Vec<u8>) -> Self {
        let (t, start) = read_bytes(&value, 0);
        let certificate = t.to_vec().into();
        let (t, _) = read_bytes(&value, start);
        let signature = t.to_vec();
        Self {
            certificate,
            signature,
        }
    }
}

pub trait Tls {
    type CX;
    type SX;
    type S: SigningScheme;

    /// Returns (certificate chain, root CA public key, root CA private key, end entity private key)
    fn make_cert_chain() -> (
        Vec<SignedCertificate>,
        <Self::S as SigningScheme>::VerifyingKey,
        <Self::S as SigningScheme>::SigningKey,
        <Self::S as SigningScheme>::SigningKey,
    );

    fn _make_cert_chain(
        mut scheme: &mut Self::S,
    ) -> (
        Vec<SignedCertificate>,
        <Self::S as SigningScheme>::VerifyingKey,
        <Self::S as SigningScheme>::SigningKey,
        <Self::S as SigningScheme>::SigningKey,
    ) {
        let (sk_root, pk_root) = scheme.keygen();
        let (sk_int, pk_int) = scheme.keygen();
        let (sk_end, pk_end) = scheme.keygen();

        let mut certs: Vec<SignedCertificate> = Vec::new();

        certs.push(
            Certificate {
                issuer_name: "intermediate-ca".to_string(),
                subject_name: "end-entity".to_string(),
                subject_pk: pk_end.to_bytes(),
            }
            .sign(scheme, &sk_int),
        );

        certs.push(
            Certificate {
                issuer_name: "root-ca".to_string(),
                subject_name: "intermediate-ca".to_string(),
                subject_pk: pk_int.to_bytes(),
            }
            .sign(scheme, &sk_root),
        );

        certs.push(
            Certificate {
                issuer_name: "self-signed".to_string(),
                subject_name: "root-ca".to_string(),
                subject_pk: pk_root.to_bytes(),
            }
            .sign(scheme, &sk_root),
        );

        (certs, pk_root, sk_root, sk_end)
    }

    fn client_transcript(client_ctx: &mut Self::CX, stream: &mut TcpStream);
    fn server_certificate(server_ctx: &mut Self::SX, stream: &mut TcpStream);
    fn server_certificate_verify(server_ctx: &mut Self::SX, stream: &mut TcpStream);
    fn client_verify(client_ctx: &mut Self::CX, stream: &mut TcpStream) -> bool;
}
