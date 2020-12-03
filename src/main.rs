use openssl::pkcs7;
use openssl::stack;
use openssl::x509::store;
use plist::Dictionary;
use plist::Value;
use std::fs;
use std::io::Cursor;
use std::iter;
use std::path::PathBuf;
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

trait Call {
    fn call<F, B>(&mut self, fun: F) -> B
    where
        F: FnOnce(&mut Self) -> B;
}

impl<T> Call for T {
    fn call<F, B>(&mut self, fun: F) -> B
    where
        F: FnOnce(&mut Self) -> B,
    {
        fun(self)
    }
}

#[allow(non_snake_case)]
#[derive(Debug)]
struct MobileconfWifi {
    // pointer to the certificate to use for this connection
    PayloadCertificateAnchorUUID: Vec<String>,
    TLSTrustedServerNames: Vec<String>,
    UserName: String,
    UserPassword: String,
    SSID: String,
    TTLSInnerAuthentication: String,
}

#[allow(non_snake_case)]
impl MobileconfWifi {
    #[allow(non_snake_case)]
    fn parse(v: &Value) -> Result<Self, String> {
        let dict = v.as_dictionary().expect("");

        let get_string = |dict: &Dictionary, key| {
            dict.get(key)
                .and_then(|x| x.as_string().map(|x| x.to_string()))
                .ok_or(key)
        };

        if let Result::Ok(typ) = get_string(dict, "PayloadType") {
            if typ != "com.apple.wifi.managed".to_string() {
                return Result::Err("Not a wifi".to_string());
            }
        }

        let EAPClientConfiguration = dict
            .get("EAPClientConfiguration")
            .ok_or("no EAPClientConfiguration")
            .and_then(|x| x.as_dictionary().ok_or("EAPClientConfiguration not a dict"))?;

        let PayloadCertificateAnchorUUID = EAPClientConfiguration
            .get("PayloadCertificateAnchorUUID")
            .ok_or("no PayloadCertificateAnchorUUID")
            .and_then(|x| x.as_array().ok_or("no PayloadCertificateAnchorUUID array"))
            .map(|vec| {
                vec.iter()
                    .filter_map(|val| val.as_string())
                    .map(|x| x.to_string())
                    .collect()
            })?;

        let TLSTrustedServerNames = match EAPClientConfiguration.get("TLSTrustedServerNames") {
            Some(tls_servers) => tls_servers
                .as_array()
                .map(|vec| {
                    vec.iter()
                        .filter_map(|val| val.as_string())
                        .map(|x| x.to_string())
                        .collect()
                })
                .ok_or("TLSTrustedServerNames"),
            None => Result::Ok(Vec::new()),
        }?;

        let UserName = get_string(EAPClientConfiguration, "UserName")?;

        let UserPassword = get_string(EAPClientConfiguration, "UserPassword")?;

        let SSID = get_string(dict, "SSID_STR")?;

        let TTLSInnerAuthentication =
            get_string(EAPClientConfiguration, "TTLSInnerAuthentication")?;

        Result::Ok(MobileconfWifi {
            PayloadCertificateAnchorUUID,
            TLSTrustedServerNames,
            UserName,
            UserPassword,
            SSID,
            TTLSInnerAuthentication,
        })
    }
}

fn partition_results<A, B, T>(v: T) -> (Vec<A>, Vec<B>)
where
    T: iter::Iterator<Item = Result<A, B>>,
{
    let (oks, errs): (Vec<_>, Vec<_>) = v.into_iter().partition(Result::is_ok);

    (
        oks.into_iter()
            .map(|x| match x {
                Result::Ok(o) => o,
                Result::Err(_) => panic!(),
            })
            .collect(),
        errs.into_iter()
            .map(|x| match x {
                Result::Err(e) => e,
                Result::Ok(_) => panic!(),
            })
            .collect(),
    )
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
        .expect("extracted");

    let plist = Value::from_reader(Cursor::new(xml)).expect("plist");
    let dict = plist.as_dictionary();
    println!(
        "PayloadDescription: {}",
        dict.and_then(|d| d.get("PayloadDescription"))
            .and_then(|x| x.as_string())
            .expect("")
    );

    let (wifis, errs): (Vec<_>, Vec<_>) = dict
        .and_then(|d| d.get("PayloadContent"))
        .and_then(|v| v.as_array())
        .expect("array of contents")
        .into_iter()
        .map(|v| MobileconfWifi::parse(v))
        .call(|x| partition_results(x));

    println!("Found wifis: {:#?}", wifis);
    println!("Errs: {:?}", errs);
}
