pub trait SigningScheme {
    type SigningKey;
    type VerifyingKey;
    type Signature;

    fn keygen(&mut self) -> (Self::SigningKey, Self::VerifyingKey);
    fn sign(&mut self, sk: &Self::SigningKey, m: &str) -> Self::Signature;
    fn verify(&mut self, pk: &Self::VerifyingKey, m: &str, t: &Self::Signature) -> bool;
}
