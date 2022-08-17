use clap::{ArgGroup, Parser};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey,
};
use sha3::{Digest, Keccak256};
use std::fs;

/// Compute the Keccak-256 hash of input bytes.
fn keccak256<S>(bytes: S) -> [u8; 32]
where
    S: AsRef<[u8]>,
{
    let mut hasher = Keccak256::new();
    Digest::update(&mut hasher, bytes.as_ref());
    hasher.finalize().into()
}

#[derive(Parser)]
#[clap(
    name = "rsa crypto tools",
    version = "0.1.0",
    about = "provide encrypt/decrypt/sign/verify methods"
)]
#[clap(group(ArgGroup::new("op_type").required(true).args(&["enc","dec","sign","verify"])))]
struct Args {
    /// encrypt data by public key
    #[clap(long)]
    enc: bool,

    /// decrypt data by private key
    #[clap(long)]
    dec: bool,

    /// sign data by private key
    #[clap(long)]
    sign: bool,

    /// verify signature with data && public key
    #[clap(long, value_name = "Signature")]
    verify: Option<String>,

    /// data ready to be en/decrypt.
    data: String,

    /// pub/pri pem key file path
    key_path: Option<String>,
}

fn main() {
    let args = Args::parse();

    // encrypt by public key , decrypt by private key:

    if args.enc {
        // encrypt data by public key
        let pub_path = args.key_path.clone().unwrap_or(String::from("./pub.pem"));

        let rsa_pub_pem = fs::read_to_string(pub_path).expect("failed to read pub key pem file");
        let pub_key = RsaPublicKey::from_public_key_pem(&rsa_pub_pem).unwrap();

        println!("encrypt: {}", args.data);

        let mut rng = rand::thread_rng();
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let enc_data = pub_key
            .encrypt(&mut rng, padding, args.data.as_bytes())
            .expect("pub key encrypt error");

        println!("result: {}", hex::encode(&enc_data));
    } else if args.dec {
        // decrypt data by private key
        let priv_path = args.key_path.unwrap_or(String::from("./pri.pem"));
        let rsa_priv_pem =
            fs::read_to_string(priv_path).expect("failed to read private key pem file");
        let priv_key = RsaPrivateKey::from_pkcs8_pem(&rsa_priv_pem).unwrap();

        let encrypted_data = hex::decode(args.data).expect("hex decode data failed");
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let dec_data = priv_key
            .decrypt(padding, &encrypted_data)
            .expect("failed to decrypt");

        println!(
            "decrypt: {}",
            String::from_utf8(dec_data.clone()).expect("error decrypt data")
        );
    } else if args.sign {
        // sign data by private key
        let priv_path = args.key_path.unwrap_or(String::from("./pri.pem"));
        let rsa_priv_pem =
            fs::read_to_string(priv_path).expect("failed to read private key pem file");
        let priv_key = RsaPrivateKey::from_pkcs8_pem(&rsa_priv_pem).unwrap();

        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA3_256));
        let digest_in = keccak256(args.data);
        let signed_data = priv_key
            .sign(padding, &digest_in)
            .expect("failed to sign data with private key");

        println!("signature: {}", hex::encode(signed_data));
    } else if args.verify.is_some() {
        let pub_path = args.key_path.clone().unwrap_or(String::from("./pub.pem"));

        let rsa_pub_pem = fs::read_to_string(pub_path).expect("failed to read pub key pem file");
        let pub_key = RsaPublicKey::from_public_key_pem(&rsa_pub_pem).unwrap();

        let signature_object_string = args.verify.expect("empty signature.");
        let signature =
            hex::decode(signature_object_string).expect("hex decode signature data failed");
        // let origin_data = args.data;
        let digest_in = keccak256(args.data);
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA3_256));

        pub_key
            .verify(padding, &digest_in, &signature)
            .expect("verify signature error");

        println!("verify signature success");
    } else {
        panic!("not possible");
    }
}
