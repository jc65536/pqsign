use ed25519_dalek::SigningKey;

use crate::signing_scheme::{SigningScheme, ToBytes};

pub struct Eddsa;

pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl ToBytes for VerifyingKey {
    fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self.0.to_bytes())
    }
}

impl From<Vec<u8>> for VerifyingKey {
    fn from(value: Vec<u8>) -> Self {
        VerifyingKey(ed25519_dalek::VerifyingKey::from_bytes(&value.try_into().unwrap()).unwrap())
    }
}

pub struct Signature(ed25519_dalek::Signature);

impl ToBytes for Signature {
    fn to_bytes(&self) -> Vec<u8> {
        Vec::from(self.0.to_bytes())
    }
}

impl From<Vec<u8>> for Signature {
    fn from(value: Vec<u8>) -> Self {
        Signature(ed25519_dalek::Signature::from_bytes(
            &value.try_into().unwrap(),
        ))
    }
}

impl SigningScheme for Eddsa {
    type SigningKey = ed25519_dalek::SigningKey;

    type VerifyingKey = VerifyingKey;

    type Signature = Signature;

    fn keygen(&mut self) -> (Self::SigningKey, Self::VerifyingKey) {
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        (sk, VerifyingKey(pk))
    }

    fn sign(&mut self, sk: &Self::SigningKey, m: &[u8]) -> Self::Signature {
        use ed25519_dalek::Signer;
        Signature(sk.sign(m))
    }

    fn verify(
        &mut self,
        VerifyingKey(pk): &Self::VerifyingKey,
        m: &[u8],
        Signature(t): &Self::Signature,
    ) -> bool {
        use ed25519_dalek::Verifier;
        pk.verify(m, t).is_ok()
    }
}
