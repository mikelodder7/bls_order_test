use amcl::arch::Chunk;
use amcl::bls381::{
    big::BIG,
    dbig::DBIG,
    ecp2::ECP2,
    pair::{ate2, fexp},
    rom
};
use hash2curve::{HashToCurveXmd, DomainSeparationTag, bls381g1::Bls12381G1Sswu};
use rand::prelude::*;

pub const MODULUS: BIG = BIG { w: rom::MODULUS };
pub const CURVE_ORDER: BIG = BIG { w: rom::CURVE_ORDER };


fn main() {

    // let mut modulus = MODULUS;
    // let mut curve_order = CURVE_ORDER;
    // println!("MODULUS                = {}", modulus.to_hex());
    // println!("CURVE_ORDER            = {}", curve_order.to_hex());
    let g2 = ECP2::generator();

    let mut s1 = gen_private_key_mod_order();
    let p1 = g2.mul(&s1);

    let mut s2 = gen_private_key_curve_order();
    let p2 = g2.mul(&s2);

    let dst = DomainSeparationTag::new(b"bls_test", None, None, None).unwrap();
    let hasher = Bls12381G1Sswu::new(dst);

    let msg = b"This is a test of BLS to see if curve order or field order matters";
    let hash_msg = hasher.hash_to_curve_xmd::<sha2::Sha256>(msg).unwrap().0;

    let mut sig1 = hash_msg.mul(&s1);
    sig1.neg();
    let mut sig2 = hash_msg.mul(&s2);
    sig2.neg();

    let temp1 = fexp(&ate2(&g2, &sig1, &p1, &hash_msg));
    let temp2 = fexp(&ate2(&g2, &sig2, &p2, &hash_msg));

    println!("Secret Key Modulus     = {}", s1.to_hex());
    println!("Public Key Modulus     = {}", p1.to_hex());
    println!("Using modulus          = {}", temp1.isunity());
    println!("Secret Key Curve Order = {}", s2.to_hex());
    println!("Public Key Curve Order = {}", p2.to_hex());
    println!("Using curve order      = {}", temp2.isunity());
}

fn gen_private_key_mod_order() -> BIG {
    gen_random(96, &MODULUS)
}

fn gen_private_key_curve_order() -> BIG {
    gen_random(64, &CURVE_ORDER)
}

fn gen_random(bytes: usize, modulus: &BIG) -> BIG {
    let mut rng = thread_rng();
    let mut data = vec![0u8; bytes];
    rng.fill_bytes(data.as_mut_slice());
    byte_array_to_big(data.as_slice(), modulus)
}

fn byte_array_to_big(bytes: &[u8], modulus: &BIG) -> BIG {
    let mut num = DBIG::new();
    for b in bytes.iter() {
        num.shl(8);
        num.w[0] += *b as Chunk;
    }

    num.dmod(modulus)
}
