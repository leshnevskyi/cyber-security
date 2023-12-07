use clap::Parser;
use openssl::rsa::{Padding, Rsa};
use rc5::{RC5WordSize, RC5};
use std::time::Instant;

#[macro_use]
extern crate prettytable;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Data file path
    #[arg(short, long)]
    data: String,

    /// Number of iterations
    #[arg(short, long, default_value_t = 100)]
    iterations: usize,
}

fn measure_execution_time<F>(mut func: F) -> u128
where
    F: FnMut() -> (),
{
    let start = Instant::now();
    func();
    Instant::now().duration_since(start).as_micros()
}

fn main() {
    let cli_args = CliArgs::parse();
    let data = std::fs::read(cli_args.data).expect("Cannot read data from file");

    let rc5 = RC5::new(RC5WordSize::Bits64, 12, 16);
    let rc5_key = rc5.generate_key(b"#seniv #komison #povtorka");

    let rc5_cypher: Vec<u8> = rc5.encrypt_cbc_pad(&data, &rc5_key).0;

    let rsa_keypair = Rsa::generate(2048).expect("Cannot generate RSA key pair");
    let rsa_private_key_pem = rsa_keypair
        .private_key_to_pem()
        .expect("Cannot serialize private key to PEM-encoded structure");
    let rsa_private_key = Rsa::private_key_from_pem(&rsa_private_key_pem)
        .expect("Cannot deserialize private key from PEM-encoded structure");
    let rsa_public_key_pem = rsa_keypair
        .public_key_to_pem_pkcs1()
        .expect("Cannot serialize public key to PEM-encoded structure");
    let rsa_pubkey = Rsa::public_key_from_pem_pkcs1(&rsa_public_key_pem)
        .expect("Cannot deserialize public key from PEM-encoded structure");

    let mut rsa_cypher = vec![0; rsa_pubkey.size() as usize];
    let mut rsa_decrypted = vec![0; rsa_keypair.size() as usize];

    let mut rc5_enc_time = 0u128;
    let mut rsa_enc_time = 0u128;

    let mut rc5_dec_time = 0u128;
    let mut rsa_dec_time = 0u128;

    for _ in 0..cli_args.iterations {
        rc5_enc_time += measure_execution_time(|| {
            rc5.encrypt_cbc_pad(&data, &rc5_key);
        });

        rc5_dec_time += measure_execution_time(|| {
            rc5.decrypt_cbc_pad(&rc5_cypher, &rc5_key);
        });

        rsa_enc_time += measure_execution_time(|| {
            rsa_pubkey
                .public_encrypt(&data, &mut rsa_cypher, Padding::PKCS1)
                .expect("RSA encryption failed");
        });

        rsa_dec_time += measure_execution_time(|| {
            rsa_private_key
                .private_decrypt(&rsa_cypher, &mut rsa_decrypted, Padding::PKCS1)
                .expect("RSA decryption failed");
        });
    }

    table!(
        [
            "Algorithm",
            "Total Time (us)",
            "Encryption Time (us)",
            "Decryption Time (us)"
        ],
        [
            "RC5",
            rc5_enc_time + rc5_dec_time,
            rc5_enc_time,
            rc5_dec_time
        ],
        [
            "RSA",
            rsa_enc_time + rsa_dec_time,
            rsa_enc_time,
            rsa_dec_time
        ]
    )
    .printstd();
}
