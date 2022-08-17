use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey,
};
use std::io::{self, Write};

use clap::Parser;

#[derive(Parser)]
#[clap(
    name = "rsa generator tools",
    version = "0.1.0",
    about = "generate rsa key pair"
)]
struct Args {
    /// called by scripts, no console interactive
    #[clap(short = 's', long = "--skip")]
    skip: bool,

    /// pub/pri pem key file path, default local directory if not set.
    write_path: Option<String>,
}

fn main() {
    let args = Args::parse();
    if args.skip {
        generate(args.write_path);
    } else {
        loop {
            let mut if_continue = String::new();
            print!(
            "generate rsa key pair? Will override file `./pri.pem` && `./pub.pem` if exist. (Y/n): "
        );
            let _ = io::stdout().flush();
            io::stdin()
                .read_line(&mut if_continue)
                .expect("Failed to read line");
            let if_continue = if_continue.trim();

            if if_continue == "y" || if_continue == "Y" {
                generate(args.write_path);
                break;
            } else if if_continue == "n" || if_continue == "N" {
                break;
            }
        }
    }
}

fn generate(path: Option<String>) {
    let write_path = path.unwrap_or(String::from("."));
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

    let _ = priv_key
        .write_pkcs8_pem_file(
            format!("{}/pri.pem", &write_path).as_str(),
            rsa::pkcs8::LineEnding::LF,
        )
        .expect("write priv key pem file error");

    let _ = priv_key
        .write_public_key_pem_file(
            format!("{}/pub.pem", &write_path).as_str(),
            rsa::pkcs8::LineEnding::LF,
        )
        .expect("write pub key pem file error");
    println!(
        "Success write file to `{}/pri.pem` && `{}/pub.pem`",
        &write_path, &write_path
    );
}
