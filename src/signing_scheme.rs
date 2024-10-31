pub trait SigningScheme {
    type SigningKey;
    type VerifyingKey;
    type Signature;

    fn keygen() -> (Self::SigningKey, Self::VerifyingKey);
    fn sign(sk: &Self::SigningKey, m: &str) -> Self::Signature;
    fn verify(pk: &Self::VerifyingKey, m: &str, t: &Self::Signature) -> bool;
}
