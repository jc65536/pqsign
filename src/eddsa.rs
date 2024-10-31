use crate::signing_scheme::SigningScheme;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

pub struct Eddsa;

impl SigningScheme for Eddsa {
    type SigningKey = SigningKey;
    type VerifyingKey = VerifyingKey;
    type Signature = Signature;

    fn keygen() -> (Self::SigningKey, Self::VerifyingKey) {
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        (sk, pk)
    }

    fn sign(sk: &Self::SigningKey, m: &str) -> Self::Signature {
        use ed25519_dalek::Signer;
        sk.sign(m.as_bytes())
    }

    fn verify(pk: &Self::VerifyingKey, m: &str, t: &Self::Signature) -> bool {
        use ed25519_dalek::Verifier;
        pk.verify(m.as_bytes(), t).is_ok()
    }
}
