#[macro_use]
extern crate magic_crypt;
use clap::{self, Parser};
use log;
use magic_crypt::MagicCryptTrait;
use serde_json;
use std::{
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    path::Path,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Whether to encrypt the input file
    #[clap(short, long)]
    encrypt: bool,
    /// Key to encrypt with
    #[clap(short, long)]
    key: String,
    /// Name of the decrypted/encrypted file
    #[clap(short, long)]
    input: String,
    /// Name of the decrypted/encrypted file
    #[clap(short, long)]
    output: String,
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    let result = || -> Result<(), Box<dyn Error>> {
        if args.encrypt {
            assert_eq!(
                Path::new(&args.input)
                    .extension()
                    .and_then(OsStr::to_str)
                    .unwrap(),
                "json",
                "Input file must end in .json"
            );

            let mc = new_magic_crypt!(args.key, 256);
            let file = fs::read_to_string(args.input.clone())?;
            let json: serde_json::Value = serde_json::from_str(&file)?;
            let encrypted = mc.encrypt_str_to_base64(json.to_string());
            let mut output = File::create(args.output.clone())?;
            let _ = write!(output, "{}", &encrypted)?;
            println!("JSON file: {} encrypted to {}", args.input, args.output);
            Ok(())
        } else {
            assert_eq!(
                Path::new(&args.output)
                    .extension()
                    .and_then(OsStr::to_str)
                    .unwrap(),
                "json",
                "Output file must end in .json"
            );

            let mc = new_magic_crypt!(args.key, 256);
            let file = fs::read_to_string(args.input.clone())?;
            let decrypted = mc.decrypt_base64_to_string(&file)?;
            let json_decrypted: serde_json::Value = serde_json::from_str(&decrypted)?;
            let file = File::create(args.output.clone())?;
            let _ = serde_json::to_writer(file, &json_decrypted)?;
            println!(
                "File: {} decrypted to JSON file {}",
                args.input, args.output,
            );
            Ok(())
        }
    };

    if let Err(e) = result() {
        log::error!("{:?}", e);
    };
}
