use clap::{Args, Parser, Subcommand};
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct CliArgs {
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand, Debug)]
enum Operation {
    Keys(KeyArgs),
    Sign(SignatureArgs),
    Verify(SignatureArgs),
}

#[derive(Args, Debug)]
struct KeyArgs {
    /// Directory to save generated keys in
    #[arg(short, long)]
    dir: String,

    /// Name that will be used for files of private and public keys
    #[arg(short, long, default_value = "dsa")]
    name: String,

    /// Key size in bits that corresponds to the length of the prime `p`
    #[arg(short, long, default_value_t = 2048)]
    size: u32,
}

#[derive(Args, Debug)]
struct SignatureArgs {
    /// Data file path
    #[arg(short, long)]
    data: String,

    /// Signature file path
    #[arg(short, long)]
    signature: String,

    /// Key file path
    #[arg(short, long)]
    key: String,
}

fn main() {
    let cli_args = CliArgs::parse();

    match cli_args.operation {
        Operation::Keys(args) => {
            let key_pair = Dsa::generate(args.size).expect("Cannot generate DSA key pair");
            let private_key_pem = key_pair
                .private_key_to_pem()
                .expect("Cannot serialize private key to PEM-encoded structure");
            let public_key_pem = key_pair
                .public_key_to_pem()
                .expect("Cannot serialize public key to PEM-encoded structure");

            let private_key_path = PathBuf::from(&args.dir)
                .join(args.name)
                .with_extension("pem");
            let public_key_path = PathBuf::from(&private_key_path).with_extension("pub.pem");

            fs::write(private_key_path, private_key_pem).expect("Cannot write private key to file");
            fs::write(public_key_path, public_key_pem).expect("Cannot write public key to file");
        }

        Operation::Sign(args) => {
            let data_path = Path::new(&args.data);
            let private_key_path = Path::new(&args.key);
            let signature_path = Path::new(&args.signature);

            let data = fs::read(data_path).expect("Cannot read data from file");
            let private_key_pem =
                fs::read(private_key_path).expect("Cannot read private key from file");
            let private_key = PKey::private_key_from_pem(&private_key_pem)
                .expect("Cannot deserialize private key from PEM-encoded structure");

            let mut signer = Signer::new(MessageDigest::sha1(), &private_key)
                .expect("Cannot create signer with given private key");
            signer.update(&data).expect("Cannot feed data to signer");
            let signature = signer.sign_to_vec().expect("Signature generation failed");

            fs::write(signature_path, signature).expect("Cannot write signature to file");
        }

        Operation::Verify(args) => {
            let data_path = Path::new(&args.data);
            let public_key_path = Path::new(&args.key);
            let signature_path = Path::new(&args.signature);

            let data = fs::read(data_path).expect("Cannot read data from file");
            let signature = fs::read(signature_path).expect("Cannot read signarure from file");
            let public_key_pem =
                fs::read(public_key_path).expect("Cannot read public key from file");
            let public_key = PKey::public_key_from_pem(&public_key_pem)
                .expect("Failed to generate public key from pem file!");

            let mut verifier = Verifier::new(MessageDigest::sha1(), &public_key)
                .expect("Cannot create verifier with given public key");
            verifier
                .update(&data)
                .expect("Cannot feed data to verifier");

            match verifier
                .verify(&signature)
                .expect("Cannot verify signature")
            {
                true => println!("Signature verified"),
                false => println!("Verification failed"),
            }
        }
    }
}
