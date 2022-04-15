extern crate clap;

use clap::{Command, Arg};
use pzip::{Algorithm, Compression, PZip, Password};
use std::fs::{remove_file, File};

fn main() {
    let matches = Command::new("pz")
        .version("1.0")
        .author("Dan Watson <dcwatson@gmail.com>")
        .about("CLI for encrypting/decrypting PZip files.")
        .arg(
            Arg::new("auto")
                .short('a')
                .help("Automatically generate an encryption password"),
        )
        .arg(
            Arg::new("password")
                .short('p')
                .takes_value(true)
                .help("Password for decryption"),
        )
        .arg(Arg::new("keep").short('k').help("Keep input files"))
        .arg(Arg::new("FILE").multiple_values(true))
        .get_matches();
    let keep = matches.occurrences_of("keep") > 0;
    let password = matches
        .value_of("password")
        .expect("you must specify a password");
    for f in matches.values_of("FILE").unwrap() {
        let mut infile = File::open(f).expect("could not open input");
        if f.ends_with(".pz") {
            let outname = f.replace(".pz", "");
            let mut outfile = File::create(outname).expect("could not create output file");
            PZip::decrypt_to(&mut infile, &mut outfile, password.as_bytes())
                .expect("error decrypting");
        } else {
            let mut outname = String::from(f);
            outname.push_str(".pz");
            let mut outfile = File::create(outname).expect("could not create output file");
            let key = Password(password);
            PZip::encrypt_to(
                &mut infile,
                &mut outfile,
                Algorithm::AesGcm256,
                &key,
                Compression::Gzip,
            )
            .expect("error encrypting");
        }
        if !keep {
            remove_file(f).ok();
        }
    }
}
