//-
// Copyright (c) 2016, Jason Lingle
//
// Permission to  use, copy,  modify, and/or distribute  this software  for any
// purpose  with or  without fee  is hereby  granted, provided  that the  above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE  IS PROVIDED "AS  IS" AND  THE AUTHOR DISCLAIMS  ALL WARRANTIES
// WITH  REGARD   TO  THIS  SOFTWARE   INCLUDING  ALL  IMPLIED   WARRANTIES  OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT  SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL,  DIRECT,   INDIRECT,  OR  CONSEQUENTIAL  DAMAGES   OR  ANY  DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF  CONTRACT, NEGLIGENCE  OR OTHER  TORTIOUS ACTION,  ARISING OUT  OF OR  IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

extern crate gpgme;
extern crate uuid;
extern crate getopts;

use std::env;
use std::io::{self, BufReader, BufWriter, Write, stdin, stdout, stderr};
use std::process::exit;

use getopts::Options;

mod mime;
mod pipe;
mod crypt;

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("R", "recurse-into-multipart",
                 "encrypt each item in a multipart separately \
                  (breaks Enigmail)");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            writeln!(stderr(), "Invalid usage: {}", f).unwrap();
            print_usage(stderr(), &program, &opts);
            exit(64 /* EX_USAGE */);
        }
    };

    if matches.opt_present("h") {
        print_usage(stdout(), &program, &opts);
        exit(0);
    }

    if matches.free.is_empty() {
        writeln!(stderr(), "No fingerprints given.").unwrap();
        print_usage(stderr(), &program, &opts);
        exit(64 /* EX_USAGE */);
    }

    let recurse_into_multipart = matches.opt_present("R");

    let encrypt = match crypt::GpgEncrypt::new(matches.free) {
        Ok(e) => e,
        Err(err) => {
            writeln!(stderr(), "GPG error: {}", err).unwrap();
            exit(65 /* EX_DATAERR */);
        }
    };
    match run(encrypt, recurse_into_multipart) {
        Ok(_) => (),
        Err(err) => {
            writeln!(stderr(), "Error: {}", err).unwrap();
            exit(71 /* EX_IOERR */);
        }
    }
}

fn print_usage<W : Write>(mut dst: W, program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] <fingerprint> ...", program);
    write!(dst, "{}", opts.usage(&brief)).unwrap();
}

fn run(encrypt: crypt::GpgEncrypt, recurse_into_multipart: bool)
       -> io::Result<()> {
    pipe::process_file(
        &mut try!(mime::LineReader::new(BufReader::new(stdin()))),
        &mut mime::LineWriter::new(BufWriter::new(stdout())),
        encrypt, pipe::UuidSeparatorGen, recurse_into_multipart)
}
