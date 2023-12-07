use clap::{Args, Parser, Subcommand, ValueEnum};
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct CliArgs {
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand, Debug)]
enum Operation {
    Keys(KeyArgs),
    Encrypt(EncryptionArgs),
    Decrypt(DecryptionArgs),
}

#[derive(Args, Debug)]
struct KeyArgs {
    /// Directory to save generated keys in
    #[arg(short, long)]
    dir: String,

    /// Name that will be used for files of private and public keys
    #[arg(short, long, default_value = "rsa")]
    name: String,

    /// Key size in bits
    #[arg(short, long, default_value_t = 4096)]
    size: u32,
}

#[derive(ValueEnum, Clone, Debug)]
enum KeyType {
    Private,
    Public,
}

#[derive(Args, Debug)]
struct EncryptionArgs {
    /// Data file path
    #[arg(short, long)]
    input: String,

    /// Encrypted file path
    #[arg(short, long)]
    output: String,

    /// Public key file path
    #[arg(short, long)]
    key: String,
}

#[derive(Args, Debug)]
struct DecryptionArgs {
    /// Encrypted file path
    #[arg(short, long)]
    input: String,

    /// Decrypted file path
    #[arg(short, long)]
    output: String,

    /// Public key file path
    #[arg(short, long)]
    key: String,
}

fn main() {
    let cli_args = CliArgs::parse();

    match cli_args.operation {
        Operation::Keys(args) => {
            let key_pair = Rsa::generate(args.size).expect("Cannot generate RSA key pair");
            let private_key_pem = key_pair
                .private_key_to_pem()
                .expect("Cannot serialize private key to PEM-encoded structure");
            let public_key_pem = key_pair
                .public_key_to_pem_pkcs1()
                .expect("Cannot serialize public key to PEM-encoded structure");

            let private_key_path = PathBuf::from(&args.dir)
                .join(args.name)
                .with_extension("pem");
            let public_key_path = PathBuf::from(&private_key_path).with_extension("pub.pem");

            fs::write(private_key_path, private_key_pem).expect("Cannot save private key");
            fs::write(public_key_path, public_key_pem).expect("Cannot save public key");
        }

        Operation::Encrypt(args) => {
            let data_path = Path::new(&args.input);
            let data = fs::read(data_path).expect("Cannot read input data from file");

            let public_key_path = Path::new(&args.key);
            let public_key_pem =
                fs::read(public_key_path).expect("Cannot read public key from file");
            let public_key = Rsa::public_key_from_pem_pkcs1(&public_key_pem)
                .expect("Cannot deserialize public key from PEM-encoded structure");

            let mut cypher: Vec<u8> = vec![0; public_key.size() as usize];
            let cypher_len = public_key
                .public_encrypt(&data, &mut cypher, Padding::PKCS1)
                .expect("Encryption failed. Data may be too large for key size");
            cypher.truncate(cypher_len);

            let cypher_path = Path::new(&args.output);
            fs::write(cypher_path, cypher).expect("Failed to save decrypted data to file");
        }

        Operation::Decrypt(args) => {
            let cypher_path = Path::new(&args.input);
            let cypher = fs::read(cypher_path).expect("Cannot read encrypted data from file");

            let private_key_path = Path::new(&args.key);
            let private_key_pem =
                fs::read(private_key_path).expect("Cannot read private key from file");
            let private_key = Rsa::private_key_from_pem(&private_key_pem)
                .expect("Cannot deserialize private key from PEM-encoded structure");

            let mut data: Vec<u8> = vec![0; private_key.size() as usize];
            let data_len = private_key
                .private_decrypt(&cypher, &mut data, Padding::PKCS1)
                .unwrap();
            data.truncate(data_len);

            let data_path = Path::new(&args.output);
            fs::write(data_path, data).expect("Cannot write data to file");
        }
    };
}
