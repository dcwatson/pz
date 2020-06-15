extern crate clap;

use clap::{App, Arg};

fn main() {
    let matches = App::new("pz")
        .version("1.0")
        .author("Dan Watson <dcwatson@gmail.com>")
        .about("CLI for encrypting/decrypting PZip files.")
        .arg(
            Arg::with_name("compress")
                .short("c")
                .help("Force decompression"),
        )
        .arg(Arg::with_name("FILE").multiple(true))
        .get_matches();
    for f in matches.values_of("FILE").unwrap() {
        println!("{}", f);
    }
}
