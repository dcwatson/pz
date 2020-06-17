extern crate clap;

use clap::{App, Arg};
use pzip::PZip;
use std::fs::{File, remove_file};

fn main() {
    let matches = App::new("pz")
        .version("1.0")
        .author("Dan Watson <dcwatson@gmail.com>")
        .about("CLI for encrypting/decrypting PZip files.")
        .arg(
            Arg::with_name("auto")
                .short("a")
                .help("Automatically generate an encryption password"),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .takes_value(true)
                .help("Password for decryption"),
        )
        .arg(
            Arg::with_name("keep").short("k").help("Keep input files")
        )
        .arg(Arg::with_name("FILE").multiple(true))
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
            PZip::decrypt(&mut infile, &mut outfile, password.as_bytes()).expect("error decrypting");
        } else {
            let mut outname = String::from(f);
            outname.push_str(".pz");
            let mut outfile = File::create(outname).expect("could not create output file");
            PZip::encrypt(&mut infile, &mut outfile, password.as_bytes()).expect("error encrypting");
        }
        if !keep {
            remove_file(f).ok();
        }
    }
}
