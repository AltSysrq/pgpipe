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

//! Implements the MIME => PGP/MIME pipeline.
//!
//! This module itself does not know how to encrypt messages; this is found in
//! the `crypt` module.
//!
//! Relevant standards:
//!   [RFC 2045] Standard content types
//!   [RFC 2046] Multipart structure
//!   [RFC 3156] PGP/MIME
//!   [RFC 3851] S/MIME

use std::ascii::AsciiExt;
use std::io::{BufRead,Read,Result,Write};

use uuid::Uuid;

use mime;

/// Maximum depth of multipart nesting before we simply copy the whole
/// multipart verbatim instead of recursing.
const MAX_DEPTH : u32 = 256;
/// The maximum number of headers that will be buffered into memory.
const MAX_HEADERS : usize = 256;

/// UW-IMAP inserts a message at the start of UNIX mboxes which it uses to
/// store metadata; we therefore don't want to touch that message at all. We
/// identify it by looking for this specific `Subject` line.
const UWIMAP_SUBJECT : &'static str =
    " DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA";

// Header constants
const CONTENT_PREFIX : &'static str = "Content-";
const CONTENT_TYPE : &'static str = "Content-Type";
const SUBJECT : &'static str = "Subject";

const APPLICATION : &'static str = "application";
const MULTIPART : &'static str = "multipart";

const ENCRYPTED : &'static str = "encrypted";
const PGP : &'static str = "pgp";
const PGP_ENCRYPTED : &'static str = "pgp-encrypted";
const PGP_KEYS : &'static str = "pgp-keys";
const PGP_SIGNATURE : &'static str = "pgp-signature";
const PKCS10 : &'static str = "pkcs-10";
const PKCS7_MIME : &'static str = "pkcs7-mime";
const PKCS7_SIGNATURE : &'static str = "pkcs7-signature";
const SIGNATURE : &'static str = "signature";
const SIGNED : &'static str = "signed";

/// Abstracts away the process of encrypting a stream bytes.
pub trait Encrypt {
    /// Encrypts the entirety of the `src` stream into `dst`.
    fn encrypt<R : Read + Send, W : Write + Send>(
        &mut self, src: &mut R, dst: &mut W) -> Result<()>;
}

/// Trait for generating multipart separators.
///
/// In practical use, this will always be `UuidSeparatorGen`, but the tests
/// provide their own deterministic implementation.
pub trait SeparatorGen {
    /// Generates a new, unique multipart separator. The separator must be safe
    /// to splice into a quoted-string without escaping, and must not exceeed
    /// 70 characters in length.
    fn gen(&mut self) -> Vec<u8>;
}

/// Separator generator based on random UUIDs.
///
/// This is the standard `SeparatorGen` implementation for non-testing use.
#[derive(Clone,Copy,Debug)]
pub struct UuidSeparatorGen;
impl SeparatorGen for UuidSeparatorGen {
    fn gen(&mut self) -> Vec<u8> {
        format!("PGPipe-{}", Uuid::new_v4()).as_bytes().to_vec()
    }
}

struct Pipe<'a, R : BufRead + 'a, W : Write + 'a,
            ENC : Encrypt, SGEN : SeparatorGen> {
    src: &'a mut mime::LineReader<R>,
    dst: &'a mut mime::LineWriter<W>,
    enc: ENC,
    sgen: SGEN,
    last_ending: mime::LineEnding,
}

/// Information about the header block of a single body part.
#[derive(Clone,Debug,Default)]
struct HeaderBlock {
    /// The raw form of all headers whose name starts with "Content-".
    content_headers: Vec<(mime::LineEnding,Vec<u8>)>,
    /// Whether a "Subject" header was found with a value equal to what UW-IMAP
    /// inserts at the top of UNIX mbox files it manages. Such messages should
    /// not be altered at all.
    ///
    /// (Note that this also relies on the fact that UW-IMAP uses a pure RFC
    /// 822 message here rather than RFC 2045, since otherwise we'd end up
    /// moving the Content headers.)
    uwimap_subject_header: bool,
    /// Whether a header line starting with "Content-" was read but was
    /// truncated. In this case, that header has already been emitted, and it
    /// is not possible to move it to a PGP/MIME section, and thus the current
    /// body cannot be encrypted.
    invalid_content_header: bool,
}

impl HeaderBlock {
    /// Returns the value of the first header in this header block whose name
    /// equals `target`.
    fn get_header(&self, target: &str) -> Option<&[u8]> {
        self.content_headers.iter()
            .filter_map(|&(_, ref text)| mime::Line::split_header_slice(text))
            .filter(|&(name,_)| target.eq_ignore_ascii_case(name))
            .map(|(_,value)| value)
            .next()
    }

    /// Extracts and parses the Content-Type header.
    fn get_content_type(&self) -> Option<mime::ContentType> {
        self.get_header(CONTENT_TYPE).and_then(
            |ct| mime::parse_content_type(ct))
    }

    /// Dumps all headers captured in this block to the given `LineWriter`.
    fn dump<W : Write>(self, dst: &mut mime::LineWriter<W>)
                       -> Result<()> {
        for (ending, content) in self.content_headers {
            try!(dst.write(&mime::Line {
                class: mime::LineClass::Generic,
                ending: ending,
                text: &content,
            }));
        }
        Ok(())
    }
}

fn is_content_header(header: &mime::Line) -> bool {
    header.split_header().map_or(false, |(name,_)| {
        name.len() > CONTENT_PREFIX.len() &&
            name[..CONTENT_PREFIX.len()].eq_ignore_ascii_case(CONTENT_PREFIX)
    })
}

#[derive(Clone,Debug,PartialEq,Eq)]
enum PartHandlingStrategy {
    Plaintext,
    Encrypt,
    Multipart(Vec<u8>),
}

impl<'a, R : BufRead + Send + 'a, W : Write + Send + 'a,
     ENC : Encrypt, SGEN : SeparatorGen>
Pipe<'a, R, W, ENC, SGEN> {
    /// Returns the line ending to use for new text. This is derived from the
    /// current line if it has a line-ending, and is CRLF otherwise.
    fn line_ending(&mut self) -> mime::LineEnding {
        let ending = self.src.curr().ending;
        self.last_ending = match ending {
            mime::LineEnding::Nil => self.last_ending,
            _ => ending,
        };
        self.last_ending
    }

    /// Copies the current "section" to the output verbatim, without inspecting
    /// anything.
    ///
    /// This specifically copies all generic or truncated lines until one of
    /// greater class is encountered.
    fn copy_section_verbatim(&mut self) -> Result<()> {
        while self.src.curr().class <= mime::LineClass::Generic {
            try!(self.dst.write(&self.src.curr()));
            try!(self.src.read_next());
        }
        Ok(())
    }

    /// Reads the full header block of a body part.
    ///
    /// All headers other than content headers are copied to output unmodified.
    /// Content headers and other properties are accumulated in the returned
    /// `HeaderBlock`.
    ///
    /// Ordinarily, this terminates on the blank line following the header
    /// block (as per `mime::Line::is_blank()`). However, if an early
    /// terminator is encountered, it stops there.
    ///
    /// All lines up to but not including the line that terminated this
    /// function are consumed. That is, the current line after this returns is
    /// either > `Generic` or `is_blank()`.
    fn read_header_block(&mut self) -> Result<HeaderBlock> {
        let mut block = HeaderBlock::default();
        let mut header = Vec::new();

        // Keep going until we encounter the blank line that terminates the
        // header block, or a (somewhat unexpected) terminator of the
        // container.
        while self.src.curr().class <= mime::LineClass::Generic &&
            !self.src.curr().is_blank()
        {
            // Try to read a full header.
            if let Some((h, line)) = try!(self.src.read_header(&mut header)) {
                // Check for "Content-" prefix. Assume anything unintelligible
                // is not a content header.
                let is_content = is_content_header(&line);

                if mime::Headerness::RawLine == h {
                    // Just copy verbatim to output. If this was a content
                    // header, we need to poison the block since we won't be
                    // able to move it.
                    try!(self.dst.write(&line));
                    block.invalid_content_header |= is_content;
                } else {
                    // We read the full header correctly; see if we need to do
                    // anything special with it.
                    if is_content && block.content_headers.len() < MAX_HEADERS {
                        // Save content headers for later once we decide what
                        // to do with this body part.
                        block.content_headers.push(
                            (line.ending, line.text.to_vec()));
                    } else {
                        // Not a header we're interested in moving, emit
                        // verbatim.
                        try!(self.dst.write(&line));

                        // If this _was_ a content header, but we overflowed
                        // the maximum header count, poison the block since we
                        // can't move everything.
                        block.invalid_content_header |= is_content;

                        // Check whether this is the UW-IMAP metadata subject
                        // line.
                        block.uwimap_subject_header |=
                            line.split_header().map_or(false, |(name,val)| {
                                SUBJECT.eq_ignore_ascii_case(name) &&
                                UWIMAP_SUBJECT.as_bytes() == val
                            });
                    }
                }
            } else {
                // Stray line; probably a truncated continuation.
                // Just copy to output.
                assert!(self.src.curr().class <= mime::LineClass::Generic);
                try!(self.dst.write(&self.src.curr()));
                // Poison block if it looks like a content header
                block.invalid_content_header |=
                    is_content_header(&self.src.curr());
                try!(self.src.read_next());
            }
        }

        Ok(block)
    }

    /// Adds a note to the output in the form of an `X-PGPipe` header.
    fn note(&mut self, message: &str) -> Result<()> {
        let line = format!("X-PGPipe: {}", message);
        self.puts(&line)
    }

    /// Writes an arbitrary string to the output, using the prevailing line
    /// ending.
    fn puts(&mut self, text: &str) -> Result<()> {
        let ending = self.line_ending();
        self.dst.write(&mime::Line {
            class: mime::LineClass::Generic,
            ending: ending,
            text: text.as_bytes(),
        })
    }

    /// Examines the given header block and the current multipart nesting
    /// depth, and determines what to do with the rest of the body.
    ///
    /// In unusual circumstances, will add a note to the output header block
    /// explaining its decision.
    fn choose_strategy(&mut self, block: &HeaderBlock, depth: u32)
                       -> Result<PartHandlingStrategy> {
        Ok(if block.uwimap_subject_header {
            PartHandlingStrategy::Plaintext
        } else if block.invalid_content_header {
            try!(self.note("Not encrypted because of oversized or corrupt \
                            content header."));
            PartHandlingStrategy::Plaintext
        } else if let Some(content_type) = block.get_content_type() {
            if content_type.is_toplevel_type(MULTIPART) {
                if content_type.is_subtype(ENCRYPTED) ||
                    content_type.is_subtype(SIGNED) ||
                    content_type.is_subtype(SIGNATURE)
                {
                    // This multipart was produced by PGP/MIME or S/MIME, leave
                    // it alone.
                    PartHandlingStrategy::Plaintext
                } else if depth > MAX_DEPTH {
                    try!(self.note("Multipart too deep, skipping"));
                    PartHandlingStrategy::Plaintext
                } else if let Some(boundary) = content_type.boundary {
                    PartHandlingStrategy::Multipart(boundary)
                } else {
                    try!(self.note("Multipart has no boundary, \
                                    treating as opaque"));
                    PartHandlingStrategy::Plaintext
                }
            } else if content_type.is_toplevel_type(APPLICATION) {
                // Check for things inserted by PGP/MIME, S/MIME, and the older
                // "application/gpg" thing.
                if content_type.is_subtype(PGP) ||
                    content_type.is_subtype(PGP_ENCRYPTED) ||
                    content_type.is_subtype(PGP_KEYS) ||
                    content_type.is_subtype(PGP_SIGNATURE) ||
                    content_type.is_subtype(PKCS10) ||
                    content_type.is_subtype(PKCS7_MIME) ||
                    content_type.is_subtype(PKCS7_SIGNATURE) ||
                    content_type.is_subtype(SIGNATURE)
                {
                    // Leave alone; we'd either double-encrypt something or
                    // obscure a signature.
                    PartHandlingStrategy::Plaintext
                } else  {
                    // No special handling needed, encrypt.
                    // Note that this ends up wrapping the "traditional"
                    // plaintext format since the only way to detect that is to
                    // actually read the body.
                    PartHandlingStrategy::Encrypt
                }
            } else {
                // No special handling needed, encrypt away
                PartHandlingStrategy::Encrypt
            }
        } else {
            try!(self.note("Assuming Content-Type: text/plain; encrypting"));
            PartHandlingStrategy::Encrypt
        })
    }

    /// Processes the current body part.
    ///
    /// Specifically, this reads the current header block, decides what to do
    /// with it, then switches to the appropriate sub-process.
    fn process_body_part(&mut self, depth: u32) -> Result<()> {
        let headers = try!(self.read_header_block());

        match try!(self.choose_strategy(&headers, depth)) {
            PartHandlingStrategy::Plaintext => self.process_plaintext(headers),
            PartHandlingStrategy::Encrypt => self.process_encrypt(headers),
            PartHandlingStrategy::Multipart(boundary) =>
                self.process_multipart(headers, depth + 1, boundary),
        }
    }

    fn process_plaintext(&mut self, headers: HeaderBlock) -> Result<()> {
        try!(headers.dump(self.dst));
        self.copy_section_verbatim()
    }

    fn process_encrypt(&mut self, headers: HeaderBlock) -> Result<()> {
        // If there's no content, we're probably in a strange state; do nothing
        // instead.
        if self.src.curr().class > mime::LineClass::Generic {
            return self.process_plaintext(headers);
        }

        // See: [RFC 3156] Section 4

        let boundary = self.sgen.gen();

        // Instead of the original content headers, add a multipart at the end
        // of the current header block.
        try!(self.puts("Content-Type: multipart/encrypted; \
                        protocol=\"application/pgp-encrypted\";"));
        try!(self.dst.dst.write_all("\tboundary=\"".as_bytes()));
        try!(self.dst.dst.write_all(&boundary));
        try!(self.puts("\""));
        try!(self.puts(""));
        try!(self.puts("This is an OpenPGP/MIME encrypted message; it was"));
        try!(self.puts("automatically encrypted by PGPipe."));

        // Part 1: Version identification
        try!(self.dst.dst.write_all("--".as_bytes()));
        try!(self.dst.dst.write_all(&boundary));
        try!(self.puts(""));
        try!(self.puts("Content-Type: application/pgp-encrypted"));
        try!(self.puts("Content-Description: PGP/MIME version identification"));
        try!(self.puts(""));
        try!(self.puts("Version: 1"));
        try!(self.puts(""));

        // Part 2: Encrypted payload
        try!(self.dst.dst.write_all("--".as_bytes()));
        try!(self.dst.dst.write_all(&boundary));
        try!(self.puts(""));
        try!(self.puts("Content-Type: application/octet-stream;"));
        try!(self.dst.dst.write_all("\tname=\"".as_bytes()));
        try!(self.dst.dst.write_all(&boundary));
        try!(self.puts(".asc\""));
        try!(self.puts("Content-Description: OpenPGP encrypted message"));
        try!(self.puts("Content-Disposition: inline;"));
        try!(self.dst.dst.write_all("\tfilename=\"".as_bytes()));
        try!(self.dst.dst.write_all(&boundary));
        try!(self.puts(".asc\""));
        try!(self.puts(""));

        let unconsumed_ending = try!(self.encrypt_section(headers));

        // End multipart
        try!(self.puts(""));
        try!(self.dst.dst.write_all("--".as_bytes()));
        try!(self.dst.dst.write_all(&boundary));
        try!(self.puts("--"));

        // If there was a trailing line ending unconsumed, write that out now.
        if let Some(ending) = unconsumed_ending {
            try!(self.dst.write(&mime::Line {
                class: mime::LineClass::Generic,
                ending: ending,
                text: "".as_bytes()
            }));
        }

        Ok(())
    }

    fn encrypt_section(&mut self, headers: HeaderBlock)
                       -> Result<Option<mime::LineEnding>> {
        let mut header_bytes = Vec::new();
        try!(headers.dump(&mut mime::LineWriter::new(&mut header_bytes)));

        // Directly concatenate the serialised headers with the entity starting
        // at the current position. We don't insert a blank line manually,
        // because the current position _is_ that blank line and thus gets
        // included "for free".
        let mut entity_stream = mime::EntityStream::new(self.src);
        try!(self.enc.encrypt(
            &mut header_bytes[..].chain(&mut entity_stream),
            &mut self.dst.dst));
        Ok(entity_stream.unconsumed_line_ending())
    }

    fn process_multipart(&mut self, headers: HeaderBlock, depth: u32,
                         boundary: Vec<u8>) -> Result<()> {
        try!(headers.dump(self.dst));

        let old_boundary = self.src.set_multipart_delim(Some(boundary));
        // Read up to the terminating delimiter (--DELIM--)
        let res = self.process_multipart_inner(depth);
        self.src.set_multipart_delim(old_boundary);
        try!(res);
        // Copy the data that is permitted to follow the terminator
        try!(self.copy_section_verbatim());

        Ok(())
    }

    fn process_multipart_inner(&mut self, depth: u32) -> Result<()> {
        // Copy data before start of first part.
        try!(self.copy_section_verbatim());
        loop {
            let class = self.src.curr().class;
            assert!(class > mime::LineClass::Generic);
            // Pass delimiter/terminator through and consume
            if class == mime::LineClass::MultipartDelim ||
                class == mime::LineClass::MultipartEnd
            {
                try!(self.dst.write(&self.src.curr()));
                try!(self.src.read_next());
            }
            // This multipart is done unless we're on a MultipartDelim.
            if class > mime::LineClass::MultipartDelim {
                break;
            }

            // Start of new body part
            try!(self.process_body_part(depth));
        }
        Ok(())
    }

    fn process_file(&mut self) -> Result<()> {
        while mime::LineClass::Eof != self.src.curr().class {
            while mime::LineClass::MessageStart == self.src.curr().class {
                try!(self.dst.write(&self.src.curr()));
                try!(self.src.read_next());
            }

            try!(self.process_body_part(0));
            self.src.set_multipart_delim(None);
        }
        Ok(())
    }
}

/// Processes all lines in `src`, writing to `dst`.
pub fn process_file<R : BufRead + Send, W : Write + Send,
                    ENC : Encrypt, SGEN : SeparatorGen>
    (src: &mut mime::LineReader<R>, dst: &mut mime::LineWriter<W>,
     enc: ENC, sgen: SGEN) -> Result<()>
{
    Pipe { src: src, dst: dst, enc: enc, sgen: sgen,
           last_ending: mime::LineEnding::CRLF,
    }.process_file()
}

#[cfg(test)]
mod test {
    use std::io::{self,Read,Result,Write};
    use std::str::from_utf8;

    use mime;
    use super::*;
    use super::{Pipe,HeaderBlock};

    #[derive(Clone,Copy,Debug,Default)]
    struct DetSeparatorGen {
        counter: u32,
    }

    impl SeparatorGen for DetSeparatorGen {
        fn gen(&mut self) -> Vec<u8> {
            self.counter += 1;
            format!("PGPipe-{}", self.counter).as_bytes().to_vec()
        }
    }

    struct DummyEncrypt;
    impl Encrypt for DummyEncrypt {
        fn encrypt<R : Read + Send, W : Write + Send>(
            &mut self, src: &mut R, dst: &mut W) -> Result<()>
        {
            try!(dst.write_all("<<<".as_bytes()));
            try!(io::copy(src, dst));
            try!(dst.write_all(">>>".as_bytes()));
            Ok(())
        }
    }

    fn test_header_block<'a>(input: &'a str, expected_passthrough: &str)
                             -> (mime::LineReader<&'a [u8]>, HeaderBlock) {
        let mut line_reader = mime::LineReader::new(input.as_bytes()).unwrap();
        // Skip start of UNIX mbox if present
        if mime::LineClass::MessageStart == line_reader.curr().class {
            line_reader.read_next().unwrap()
        }
        let mut passed_through = Vec::new();

        let block = {
            let mut line_writer = mime::LineWriter::new(&mut passed_through);
            let mut pipe = Pipe {
                src: &mut line_reader,
                dst: &mut line_writer,
                sgen: DetSeparatorGen::default(),
                enc: DummyEncrypt,
                last_ending: mime::LineEnding::CRLF,
            };

            pipe.read_header_block().unwrap()
        };

        assert_eq!(expected_passthrough.as_bytes(), &passed_through[..]);
        assert!(line_reader.curr().is_blank() ||
                line_reader.curr().class > mime::LineClass::Generic);
        (line_reader, block)
    }

    #[test]
    fn simple_read_header_block() {
        let (mut reader, block) = test_header_block(
            "From: jason@lin.gl\n\
             Subject: Test\n\
             \n\
             Body\n",

            "From: jason@lin.gl\n\
             Subject: Test\n");

        assert!(block.content_headers.is_empty());
        assert!(!block.uwimap_subject_header);
        assert!(!block.invalid_content_header);

        assert_eq!(mime::LineClass::Generic, reader.curr().class);
        assert!(reader.curr().is_blank());
        reader.read_next().unwrap();
        assert_eq!(mime::LineClass::Generic, reader.curr().class);
        assert_eq!("Body".as_bytes(), reader.curr().text);
    }

    #[test]
    fn uwimap_subject_detected() {
        let (_, block) = test_header_block(
            "From MAILER-DAEMON Sat May 28 21:40:44 2016\n\
             From: Mail System Internal Data <MAILER-DAEMON@localhost>\n\
             Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\n",

            "From: Mail System Internal Data <MAILER-DAEMON@localhost>\n\
             Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\n");

        assert!(block.uwimap_subject_header);
    }

    #[test]
    fn content_headers_not_copied() {
        let (_, block) = test_header_block(
            "From: jason@lin.gl\n\
             Content-Type: text/plain; charset=utf-8\n\
             Content-Transfer-Encoding: binary\n\
             Subject: Test\n",

            "From: jason@lin.gl\n\
             Subject: Test\n");

        assert_eq!(2, block.content_headers.len());
        assert!(!block.invalid_content_header);
    }

    #[test]
    fn header_block_poisoned_if_content_header_truncated() {
        let mut huge = String::with_capacity(2000);
        for _ in 0..2000 {
            huge.push('x');
        }
        let headers = format!("Content-Type: {}\n\
                               From: jason@lin.gl\n", &huge);
        let (_, block) = test_header_block(&headers, &headers);
        assert!(block.content_headers.is_empty());
        assert!(block.invalid_content_header);
    }

    fn join(strs: Vec<&str>) -> String {
        let mut output = String::new();
        for part in strs {
            output.push_str(part);
        }

        output
    }

    fn test_process(input_parts: Vec<&str>, output_parts: Vec<&str>) {
        let input = join(input_parts);
        let output = join(output_parts);

        let mut accum = Vec::new();
        {
            let mut reader = mime::LineReader::new(input.as_bytes()).unwrap();
            let mut writer = mime::LineWriter::new(&mut accum);
            process_file(&mut reader, &mut writer, DummyEncrypt,
                         DetSeparatorGen::default()).unwrap();
        }

        if &output != from_utf8(&accum).unwrap() {
            println!("Expected:\n{}\nGot:\n{}\n",
                     &output, from_utf8(&accum).unwrap());
            panic!("Didn't have the expected output.");
        }
    }

    fn test_process_untouched(parts: Vec<&str>) {
        test_process(parts.clone(), parts);
    }

    #[test]
    fn process_empty() {
        test_process_untouched(vec![""]);
    }

    const CT_MP_ENC : &'static str =
        "Content-Type: multipart/encrypted; \
         protocol=\"application/pgp-encrypted\";\n";
    const CT_PFX : &'static str =
        "\n\
         This is an OpenPGP/MIME encrypted message; it was\n\
         automatically encrypted by PGPipe.\n";
    const VERSION_ID : &'static str =
        "Content-Type: application/pgp-encrypted\n\
         Content-Description: PGP/MIME version identification\n\
         \n\
         Version: 1\n\
         \n";
    const CT_AOT : &'static str =
        "Content-Type: application/octet-stream;\n";
    const CDCD : &'static str =
        "Content-Description: OpenPGP encrypted message\n\
         Content-Disposition: inline;\n";
    const PLAIN_HW : &'static str =
        "Content-Transfer-Encoding: 8bit\n\
         Content-Type: text/plain; charset=utf-8\n\
         \n\
         hello world\n";
    const ENC_HW : &'static str =
        "\n\
         <<<Content-Transfer-Encoding: 8bit\n\
         Content-Type: text/plain; charset=utf-8\n\
         \n\
         hello world\n\
         >>>\n";

    #[test]
    fn process_encrypt_simple() {
        test_process(
            vec![
                "From: jason@lin.gl\n",
                PLAIN_HW,
            ], vec![
                "From: jason@lin.gl\n",
                CT_MP_ENC,
                "\tboundary=\"PGPipe-1\"\n",
                CT_PFX,
                "--PGPipe-1\n",
                VERSION_ID,
                "--PGPipe-1\n",
                CT_AOT,
                "\tname=\"PGPipe-1.asc\"\n",
                CDCD,
                "\tfilename=\"PGPipe-1.asc\"\n",
                ENC_HW,
                "--PGPipe-1--\n",
            ]);
    }

    #[test]
    fn missing_content_type_handled_like_text_plain() {
        test_process(
            vec![
                "From: jason@lin.gl\n\
                 \n\
                 hello world\n"
            ], vec![
                "From: jason@lin.gl\n\
                 X-PGPipe: Assuming Content-Type: text/plain; encrypting\n",
                CT_MP_ENC,
                "\tboundary=\"PGPipe-1\"\n",
                CT_PFX,
                "--PGPipe-1\n",
                VERSION_ID,
                "--PGPipe-1\n",
                CT_AOT,
                "\tname=\"PGPipe-1.asc\"\n",
                CDCD,
                "\tfilename=\"PGPipe-1.asc\"\n\
                 \n\
                 <<<\n\
                 hello world\n\
                 >>>\n\
                 --PGPipe-1--\n",
            ]);
    }

    #[test]
    fn multiparts_recursively_encrypted() {
        test_process(
            vec![
                "From: jason@lin.gl\n\
                 Content-Type: multipart/mixed; boundary=DELIM\n\
                 \n\
                 This is a multipart message.\n\
                 --DELIM\n",
                PLAIN_HW,
                "\n\
                 --DELIM\n",
                PLAIN_HW,
                "\n\
                 --DELIM--\n\
                 This is the end of the multipart message.\n"
            ], vec![
                "From: jason@lin.gl\n\
                 Content-Type: multipart/mixed; boundary=DELIM\n\
                 \n\
                 This is a multipart message.\n\
                 --DELIM\n",
                CT_MP_ENC,
                "\tboundary=\"PGPipe-1\"\n",
                CT_PFX,
                "--PGPipe-1\n",
                VERSION_ID,
                "--PGPipe-1\n",
                CT_AOT,
                "\tname=\"PGPipe-1.asc\"\n",
                CDCD,
                "\tfilename=\"PGPipe-1.asc\"\n",
                ENC_HW,
                "--PGPipe-1--\n\
                 \n\
                 --DELIM\n",
                CT_MP_ENC,
                "\tboundary=\"PGPipe-2\"\n",
                CT_PFX,
                "--PGPipe-2\n",
                VERSION_ID,
                "--PGPipe-2\n",
                CT_AOT,
                "\tname=\"PGPipe-2.asc\"\n",
                CDCD,
                "\tfilename=\"PGPipe-2.asc\"\n",
                ENC_HW,
                "--PGPipe-2--\n\
                 \n\
                 --DELIM--\n\
                 This is the end of the multipart message.\n",
            ]);
    }

    #[test]
    fn uwimap_header_message_untouched() {
        test_process_untouched(
            vec!["From MAILER-DAEMON Sat May 28 21:40:44 2016\n\
                  From: Mail System Internal Data <MAILER-DAEMON@localhost>\n\
                  Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\n\
                  \n\
                  Don't delete this message, &c &c\n"]);
    }

    #[test]
    fn application_pgp_untouched() {
        test_process_untouched(
            vec!["From: jason@lin.gl\n\
                  Content-Type: application/pgp\n\
                  \n\
                  This is a deprecated-style PGP message.\n"]);
    }

    #[test]
    fn multipart_encrypted_not_reencrypted() {
        test_process_untouched(
            vec!["From: jason@lin.gl\n\
                  Content-Type: multipart/encrypted; boundary=foo\n\
                  \n\
                  --foo\n\
                  Stuff.\n\
                  --foo--\n"]);
    }

    #[test]
    fn boundariless_multipart_passed_through() {
        test_process(
            vec![
                "From: jason@lin.gl\n\
                 Content-Type: multipart/mixed\n\
                 \n\
                 This mail client clearly doesn't understand what a\n\
                 multipart is.\n",
            ], vec![
                "From: jason@lin.gl\n\
                 X-PGPipe: Multipart has no boundary, treating as opaque\n\
                 Content-Type: multipart/mixed\n\
                 \n\
                 This mail client clearly doesn't understand what a\n\
                 multipart is.\n"
            ]);
    }
}
