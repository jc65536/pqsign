use crate::signing_scheme::SigningScheme;
use libc::{c_int, c_uint, size_t};

#[repr(C)]
struct shake256_context {
    opaque_contents: [u64; 26],
}

extern "C" {
    fn shake256_init_prng_from_seed(sc: *mut shake256_context, seed: *const u8, seed_len: size_t);

    fn shake256_init_prng_from_system(sc: *mut shake256_context) -> c_int;

    fn falcon_keygen_make(
        rng: *mut shake256_context,
        logn: c_uint,
        privkey: *mut u8,
        privkey_len: size_t,
        pubkey: *mut u8,
        pubkey_len: size_t,
        tmp: *mut u8,
        tmp_len: size_t,
    ) -> c_int;

    fn falcon_sign_dyn(
        rng: *mut shake256_context,
        sig: *mut u8,
        sig_len: *mut size_t,
        sig_type: c_int,
        privkey: *const u8,
        privkey_len: size_t,
        data: *const u8,
        data_len: size_t,
        tmp: *mut u8,
        tmp_len: size_t,
    ) -> c_int;

    fn falcon_verify(
        sig: *const u8,
        sig_len: size_t,
        sig_type: c_int,
        pubkey: *const u8,
        pubkey_len: size_t,
        data: *const u8,
        data_len: size_t,
        tmp: *mut u8,
        tmp_len: size_t,
    ) -> c_int;
}

#[derive(Clone, Copy)]
pub enum Degree {
    F512 = 9,
    F1024 = 10,
}

pub struct Falcon {
    deg: Degree,
    rng: shake256_context,
}

impl Falcon {
    pub fn new(deg: Degree, seed: Option<&[u8]>) -> Self {
        let mut rng = shake256_context {
            opaque_contents: [0; 26],
        };

        unsafe {
            match seed {
                Some(seed) => shake256_init_prng_from_seed(&mut rng, seed.as_ptr(), seed.len()),
                None => {
                    let status = shake256_init_prng_from_system(&mut rng);
                    if status != 0 {
                        shake256_init_prng_from_seed(&mut rng, [].as_ptr(), 0);
                    }
                }
            }
        }

        Self { deg, rng }
    }

    fn sk_size(&self) -> usize {
        let x = self.deg as usize;
        (if x <= 3 {
            3usize << x
        } else {
            ((10usize - (x >> 1)) << (x - 2)) + (1 << x)
        } + 1)
    }

    fn pk_size(&self) -> usize {
        let x = self.deg as usize;
        (if x <= 1 { 4usize } else { 7usize << (x - 2) } + 1)
    }

    fn sig_maxsize(&self) -> usize {
        let x = self.deg as usize;
        ((((11usize << x) + (101usize >> (10 - x))) + 7) >> 3) + 41
    }

    fn tmpsize_keygen(&self) -> usize {
        let x = self.deg as usize;
        (if x <= 3 { 272usize } else { 28usize << x } + (3usize << x) + 7)
    }

    fn tmpsize_sign(&self) -> usize {
        (78usize << self.deg as usize) + 7
    }

    fn tmpsize_verify(&self) -> usize {
        (8usize << self.deg as usize) + 1
    }
}

impl SigningScheme for Falcon {
    type SigningKey = Vec<u8>;

    type VerifyingKey = Vec<u8>;

    type Signature = Vec<u8>;

    fn keygen(&mut self) -> (Self::SigningKey, Self::VerifyingKey) {
        let mut sk: Self::SigningKey = vec![0; self.sk_size()];
        let mut pk: Self::VerifyingKey = vec![0; self.pk_size()];
        let mut tmp: Vec<u8> = vec![0; self.tmpsize_keygen()];

        unsafe {
            let status = falcon_keygen_make(
                &mut self.rng,
                self.deg as c_uint,
                sk.as_mut_ptr(),
                sk.len(),
                pk.as_mut_ptr(),
                pk.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            );

            if status != 0 {
                panic!("Falcon keygen error: {status}")
            }
        }

        (sk, pk)
    }

    fn sign(&mut self, sk: &Self::SigningKey, m: &str) -> Self::Signature {
        let mut t: Self::Signature = vec![0; self.sig_maxsize()];
        let mut t_size: size_t = t.len();
        let mut tmp: Vec<u8> = vec![0; self.tmpsize_sign()];

        unsafe {
            let status = falcon_sign_dyn(
                &mut self.rng,
                t.as_mut_ptr(),
                &mut t_size,
                1, // FALCON_SIG_COMPRESSED
                sk.as_ptr(),
                sk.len(),
                m.as_ptr(),
                m.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            );

            if status != 0 {
                panic!("Falcon sign error: {status}");
            }
        }

        t.resize(t_size, 0);

        t
    }

    fn verify(&mut self, pk: &Self::VerifyingKey, m: &str, t: &Self::Signature) -> bool {
        let mut tmp: Vec<u8> = vec![0; self.tmpsize_verify()];

        unsafe {
            let status = falcon_verify(
                t.as_ptr(),
                t.len(),
                0, // Auto-detect sig type
                pk.as_ptr(),
                pk.len(),
                m.as_ptr(),
                m.len(),
                tmp.as_mut_ptr(),
                tmp.len(),
            );

            match status {
                0 => true,
                -4 => false, // FALCON_ERR_BADSIG
                _ => panic!("Falcon verify error: {status}"),
            }
        }
    }
}
