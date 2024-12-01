pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait SigningScheme {
    type SigningKey;
    type VerifyingKey: ToBytes + From<Vec<u8>>;
    type Signature: ToBytes + From<Vec<u8>>;

    fn keygen(&mut self) -> (Self::SigningKey, Self::VerifyingKey);
    fn sign(&mut self, sk: &Self::SigningKey, m: &[u8]) -> Self::Signature;
    fn verify(&mut self, pk: &Self::VerifyingKey, m: &[u8], t: &Self::Signature) -> bool;
}
