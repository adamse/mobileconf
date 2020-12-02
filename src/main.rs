// use std::env;
use openssl::pkcs7;
use openssl::stack;
use openssl::x509::store;
use std::fs;
use std::path::PathBuf;
use std::str;
use std::vec;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "mobileconf",
    about = "Extract pertinent details from .mobileconf files."
)]
struct Args {
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn main() {
    let args = Args::from_args();

    let bytes = fs::read(args.input).expect("read mobileconf");
    let p7 = pkcs7::Pkcs7::from_der(&bytes[..]).expect("read pkcs7");

    // we just want to get the payload, these inputs gets us that.
    let stack = stack::Stack::new().expect("new cert stack");
    let store = store::X509StoreBuilder::new()
        .expect("new cert store")
        .build();
    let mut flags = pkcs7::Pkcs7Flags::empty();
    flags.insert(pkcs7::Pkcs7Flags::NOVERIFY);

    let mut xml: vec::Vec<u8> = vec::Vec::new();

    p7.verify(&stack, &store, None, Some(&mut xml), flags)
        .expect("verified");

    println!("{}", str::from_utf8(&xml[..]).expect("utf8"));
}
