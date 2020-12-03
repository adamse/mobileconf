use base64;
use openssl::pkcs7;
use openssl::stack;
use openssl::x509::store;
use plist::Dictionary;
use plist::Value;
use std::fs;
use std::io::Cursor;
use std::iter;
use std::path::PathBuf;
use std::string::String;
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

fn get_string(dict: &Dictionary, key: &str) -> Result<String, String> {
    dict.get(key)
        .ok_or(format!("missing key: {}", key))?
        .as_string()
        .ok_or(format!("key not a string: {}", key))
        .map(str::to_string)
}

#[allow(non_snake_case)]
impl MobileconfWifi {
    #[allow(non_snake_case)]
    fn parse(v: &Value) -> Result<Self, String> {
        let dict = v.as_dictionary().expect("");

        if let Result::Ok(typ) = get_string(dict, "PayloadType") {
            if typ != *"com.apple.wifi.managed" {
                return Result::Err("Not a wifi".to_string());
            }
        }

        let EAPClientConfiguration = dict
            .get("EAPClientConfiguration")
            .ok_or("no EAPClientConfiguration")?
            .as_dictionary()
            .ok_or("EAPClientConfiguration not a dict")?;

        let PayloadCertificateAnchorUUID = EAPClientConfiguration
            .get("PayloadCertificateAnchorUUID")
            .ok_or("no PayloadCertificateAnchorUUID")?
            .as_array()
            .ok_or("expected array: PayloadCertificateAnchorUUID")?
            .iter()
            .filter_map(Value::as_string)
            .map(str::to_string)
            .collect();

        let TLSTrustedServerNames = match EAPClientConfiguration.get("TLSTrustedServerNames") {
            Some(tls_servers) => tls_servers
                .as_array()
                .ok_or("expected array: TLSTrustedServerNames")
                .map(|vec| {
                    vec.iter()
                        .filter_map(Value::as_string)
                        .map(str::to_string)
                        .collect()
                }),
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

#[allow(non_snake_case)]
#[derive(Debug)]
struct MobileconfTLSCert {
    PayloadUUID: String,
    // tls cert bytes
    PayloadContent: String,
}

impl MobileconfTLSCert {
    #[allow(non_snake_case)]
    fn parse(v: &Value) -> Result<Self, String> {
        let dict = v.as_dictionary().expect("");

        if let Result::Ok(typ) = get_string(dict, "PayloadType") {
            if !(typ == *"com.apple.security.pem"
                || typ == *"com.apple.security.root")
            {
                return Result::Err("Not a TLS certificate".to_string());
            }
        }

        let PayloadUUID = get_string(dict, "PayloadUUID")?;

        let data: &[u8] = dict
            .get("PayloadContent")
            .ok_or("missing key: PayloadContent")?
            .as_data()
            .ok_or("expected data")?;

        let PayloadContent = base64::encode(data);

        Result::Ok(MobileconfTLSCert {
            PayloadUUID,
            PayloadContent,
        })
    }
}

fn partition_results<A, B, T>(v: T) -> (Vec<A>, Vec<B>)
where
    T: iter::Iterator<Item = Result<A, B>>,
{
    let mut oks = Vec::new();
    let mut errs = Vec::new();

    v.for_each(|x| match x {
      Result::Ok(ok) => oks.push(ok),
      Result::Err(err) => errs.push(err),
    });

    (oks, errs)
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
        .expect("verify and extract pkcs7 payload");

    let plist = Value::from_reader(Cursor::new(xml)).expect("plist");
    let dict = plist.as_dictionary();

    let contents = dict
        .and_then(|d| d.get("PayloadContent"))
        .and_then(|v| v.as_array())
        .expect("array of contents");

    let (wifis, errs): (Vec<_>, Vec<_>) = contents
        .iter()
        .map(|v| MobileconfWifi::parse(v))
        .call(|x| partition_results(x));
    println!("Errs: {:?}", errs);

    let (certs, errs): (Vec<_>, Vec<_>) = contents
        .iter()
        .map(|v| MobileconfTLSCert::parse(v))
        .call(|x| partition_results(x));
    println!("Errs: {:?}", errs);

    println!("Found wifis: {:#?}", wifis);
    println!("Found certs: {:#?}", certs);
}
