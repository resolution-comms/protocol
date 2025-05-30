use oqs;

fn main() {
    oqs::init();
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    let (ct, ss) = kem.encapsulate(&pk).unwrap();
    let ss2 = kem.decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss, ss2);

    println!(
        "{}, {}, {}, {}, {ss:?}",
        kem.length_public_key(),
        kem.length_secret_key(),
        kem.length_ciphertext(),
        kem.length_shared_secret()
    );
}
