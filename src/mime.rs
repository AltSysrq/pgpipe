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

//! Facilities for reading and writing MIME messages.
//!
//! This is not a full MIME parser or generator; it only supports the minimum
//! needed in order to encrypt messages. In general, anything unknown or
//! unexpected is in general simply passed verbatim to the output.
//!
//! Both UNIX and DOS line-endings are supported, and should be preserved as
//! much as possible.
//!
//! The reader and writer both work in terms of physical lines. The reader
//! knows about certain line prefices which indicate that the current section
//! has stopped.
//!
//! UNIX mbox files are automatically detected from the first line; this causes
//! the prefix "From " to be treated as a message delimiter in any context.
//! This is specifically intended for use with these files as produced by
//! uw-imap, and might not work in other contexts.
//!
//! Relevant standards:
//!   [RFC  822]        Basic definition of MIME format
//!   [RFC 2045]        Defines the Content-* headers
//!   [RFC 2046]        Defines Multipart syntax

use std::io::{BufRead,Result,Write};
use std::mem;
use std::str;

/// The maximum line size before we split the line into smaller parts. (The
/// fact that there is no line ending between them is preserved).
const MAX_LINE : usize = 1024;

/// Identifies the type of a line.
///
/// This enumeration is ordered; eg, a multipart part ends on a class >=
/// MultipartDelim, whereas a multipart itself ends on a class >= MultipartEnd.
/// (Normally this is always equality, but we do this to handle malformed
/// messages).
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum LineClass {
    /// The line was truncated because it is too long. No useful analysis of
    /// the contents can be performed.
    Truncated,
    /// The line was read fully, and did not match any active terminators.
    Generic,
    /// The line was read fully, and is a multipart delimiter.
    MultipartDelim,
    /// The line was read fully, and is a multipart terminator.
    MultipartEnd,
    /// The line was read fully, and is the start of a new message in UNIX mbox
    /// format.
    MessageStart,
    /// The end of the input was reached.
    Eof,
}

/// Indicates the ending character(s) on a line.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum LineEnding {
    /// Carraige-Return followed by Line-Feed, as required by RFC 822.
    CRLF,
    /// Bare Line-Feed, as used on sane systems.
    LF,
    /// No line ending. Either the end of the file was reached without finding
    /// one, or the line was truncated.
    Nil,
}

/// A line read from `LineReader` or written to `LineWriter`.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Line<'a> {
    /// The classification of this line.
    pub class: LineClass,
    /// The text of this line, without its line ending.
    pub text: &'a[u8],
    /// The line ending which delimited this line.
    pub ending: LineEnding,
}

/// Describes the result of trying to extract multiple lines as a header.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Headerness {
    /// The line(s) look like a complete header, as far as folding is
    /// concerned.
    Header,
    /// The line(s) are not a complete header. This could be due to the
    /// unfolded length exceeding the maximum line length, or due to a folded
    /// line appearing spuriously.
    RawLine,
}

/// Returns whether the given character is a "linear whitespace" character
/// according to RFC 822.
fn is_lwsp(ch: u8) -> bool {
    b' ' == ch || b'\t' == ch
}

impl<'a> Line<'a> {
    /// Returns whether the given line is the first line of a header (assuming
    /// it is in a header block).
    pub fn is_start_of_header(&self) -> bool {
        LineClass::Generic == self.class &&
            !self.text.is_empty() &&
            !is_lwsp(self.text[0])
    }

    /// Returns whether the given line is a header continuation (assuming it is
    /// in a header block).
    pub fn is_header_continuation(&self) -> bool {
        LineClass::Generic == self.class &&
            !self.text.is_empty() &&
            is_lwsp(self.text[0])
    }

    /// Returns whether this line is a generic blank line.
    pub fn is_blank(&self) -> bool {
        LineClass::Generic == self.class &&
            self.text.is_empty()
    }

    /// Attempts to interpret this line as a MIME header, splitting it into its
    /// name and value parts.
    ///
    /// If the header is sufficiently valid, returns a pair slices into the
    /// line which reference the name (as a string) and the value of the
    /// header. Leading whitespace in the value is not removed. Also note that
    /// the header unfolder keeps newline sequences in the logical lines, so
    /// the header value may contain line feeds.
    ///
    /// While the header name is constrained to printable ASCII, this function
    /// permits arbitrary binary data in the value.
    pub fn split_header(&self) -> Option<(&str,&[u8])> {
        // MIME's weird quoting/commenting rules do not take place before the
        // colon ending the header name.
        //
        // [RFC 822, section 3.1.2]
        //
        // > The  field-name must be composed of printable ASCII characters
        // > (i.e., characters that  have  values  between  33.  and  126.,
        // > decimal, except colon).  The field-body may be composed of any
        // > ASCII characters, except CR or LF.
        //
        // (Though note that our header unfolder preserves CR and LF in the
        // field-body.)

        let mut colon = 0;
        // Search for the colon ending the field-name. This is not a valid
        // header if we do not find one, or find a non-printable ASCII
        // character.
        loop {
            if colon >= self.text.len() {
                return None;
            }
            if b':' == self.text[colon] {
                break;
            }
            if self.text[colon] < 33 || self.text[colon] > 126 {
                return None;
            }
            colon += 1;
        }

        // field-name is invalid if empty
        if 0 == colon {
            return None;
        }

        return str::from_utf8(&self.text[0..colon]).ok().map(
            |name| (name, &self.text[colon + 1 ..]));
    }
}

/// Reads physical lines from a MIME file.
pub struct LineReader<R : BufRead> {
    src: R,
    curr_class: LineClass,
    curr_ending: LineEnding,
    curr_text: Vec<u8>,
    mbox: bool,
    multipart_delim: Option<Vec<u8>>,
}

impl<R : BufRead> LineReader<R> {
    /// Creates a new `LineReader` reading from the given source.
    ///
    /// This call implicitly reads the first line from `src`, so that `curr()`
    /// is immediately usable and to detect UNIX mbox-format files.
    pub fn new(src: R) -> Result<Self> {
        let mut this = LineReader::empty(src);
        try!(this.read_next());
        if this.curr_class == LineClass::Generic &&
            this.looking_at_mbox_start()
        {
            this.mbox = true;
            this.curr_class = LineClass::MessageStart;
        }
        Ok(this)
    }

    /// Returns the current line from this reader.
    ///
    /// This does not advance the file.
    pub fn curr(&self) -> Line {
        Line {
            class: self.curr_class,
            ending: self.curr_ending,
            text: &self.curr_text,
        }
    }

    /// Discards the current line and reads the next one.
    ///
    /// If at EOF, this essentially has no effect.
    pub fn read_next(&mut self) -> Result<()> {
        let eof = try!(self.read_next_raw());
        if eof {
            self.curr_class = LineClass::Eof;
            self.curr_text.clear();
            self.curr_ending = LineEnding::Nil;
        } else {
            self.detect_line_type();
            self.detect_line_ending();
        }
        Ok(())
    }

    /// Sets the current multipart delimiter.
    ///
    /// Returns the prior value of the delimiter, so that it can be restored
    /// later if this is due to entering a nested multipart.
    pub fn set_multipart_delim(&mut self, delim: Option<Vec<u8>>)
                               -> Option<Vec<u8>> {
        mem::replace(&mut self.multipart_delim, delim)
    }

    /// Reads a logical header line, assuming the current line is in a header
    /// block.
    ///
    /// If the current line is not the start of a header, returns None and
    /// consumes nothing. Otherwise, accumulates the header into `accum`,
    /// returning a line representing the combined text. If the header spans
    /// multiple lines, interior line endings are included, but the terminating
    /// line ending is not.
    ///
    /// A header will be terminated prematurely if any constituent physical
    /// lines were truncated, or if the combined length exceeds the maximum
    /// line length.
    ///
    /// In all cases where a line is returned, all constituent lines whose
    /// contents were added to `accum` will have been consumed.
    pub fn read_header<'a>(&mut self, accum: &'a mut Vec<u8>)
                           -> Result<Option<(Headerness, Line<'a>)>> {
        if !self.curr().is_start_of_header() {
            return Ok(None)
        }

        accum.clear();
        let mut last_ending = LineEnding::Nil;
        let mut headerness = Headerness::RawLine;
        loop {
            accum.extend_from_slice(match last_ending {
                LineEnding::Nil => "".as_bytes(),
                LineEnding::LF => "\n".as_bytes(),
                LineEnding::CRLF => "\r\n".as_bytes(),
            });
            accum.extend_from_slice(self.curr().text);
            last_ending = self.curr().ending;
            try!(self.read_next());

            if LineClass::Truncated == self.curr().class {
                break;
            }
            if !self.curr().is_header_continuation() {
                headerness = Headerness::Header;
                break;
            }
            if accum.len() > MAX_LINE {
                break;
            }
        }

        Ok(Some((headerness, Line {
            class: LineClass::Generic,
            ending: last_ending,
            text: accum,
        })))
    }

    fn empty(src: R) -> Self {
        LineReader {
            src: src,
            curr_class: LineClass::Generic,
            curr_ending: LineEnding::CRLF,
            curr_text: Vec::with_capacity(MAX_LINE),
            mbox: false,
            multipart_delim: None,
        }
    }

    fn read_next_raw(&mut self) -> Result<bool> {
        self.curr_text.clear();
        let mut done = false;
        while !done && self.curr_text.len() < MAX_LINE {
            let mut n : usize = 0;
            {
                let data = try!(self.src.fill_buf());
                if 0 == data.len() {
                    break;
                }
                while n < data.len() && self.curr_text.len() < MAX_LINE {
                    let b = data[n];
                    self.curr_text.push(b);
                    n += 1;
                    if b'\n' == b {
                        done = true;
                        break;
                    }
                }
            }

            self.src.consume(n);
        }

        Ok(0 == self.curr_text.len())
    }

    fn detect_line_type(&mut self) {
        // If the last line had no line ending, we're still in a truncated line
        if LineEnding::Nil == self.curr_ending {
            self.curr_class = LineClass::Truncated;
        } else if self.mbox && self.looking_at_mbox_start() {
            self.curr_class = LineClass::MessageStart;
        } else if let Some(class) = self.looking_at_mp_delim() {
            self.curr_class = class;
        } else {
            self.curr_class = LineClass::Generic;
        }
    }

    fn detect_line_ending(&mut self) {
        if b'\n' == *self.curr_text.last().unwrap_or(&0) {
            self.curr_text.pop();
            if b'\r' == *self.curr_text.last().unwrap_or(&0) {
                self.curr_text.pop();
                self.curr_ending = LineEnding::CRLF;
            } else {
                self.curr_ending = LineEnding::LF;
            }
        } else {
            self.curr_ending = LineEnding::Nil;
            // Don't attempt to ascribe any meaning to lines which were
            // truncated. Lines without endings may occur at EOF if the file is
            // not terminated with a newline, so we only count it truncated if
            // the text we read is the maximum buffer size.
            if MAX_LINE == self.curr_text.len() {
                self.curr_class = LineClass::Truncated;
            }
        }
    }

    fn looking_at_mbox_start(&self) -> bool {
        let from = [b'F', b'r', b'o', b'm', b' '];
        self.curr_text.len() >= from.len() &&
            from[..] == self.curr_text[0..from.len()]
    }

    fn looking_at_mp_delim(&self) -> Option<LineClass> {
        if let Some(ref delim) = self.multipart_delim {
            if self.curr_text.len() >= delim.len() + 2 &&
                [b'-', b'-'][..] == self.curr_text[0..2] &&
                delim[..] == self.curr_text[2..2+delim.len()]
            {
                if self.curr_text.len() >= delim.len() + 4 &&
                    [b'-', b'-'][..] == self.curr_text[
                        delim.len()+2..delim.len()+4] {
                    return Some(LineClass::MultipartEnd);
                } else {
                    return Some(LineClass::MultipartDelim);
                }
            }
        }
        None
    }
}

/// Line-based writer which is the inverse of `LineReader`.
///
/// For any sequence of bytes, passing each `Line` from a `LineReader` into a
/// `LineWriter` in the same order is expected to produce exactly the same byte
/// sequence.
///
/// Note that the `LineWriter` does not care about the class of each line; all
/// the information it needs is carried in the text content and the line
/// ending.
pub struct LineWriter<W : Write> {
    dst: W,
}

impl<W : Write> LineWriter<W> {
    /// Constructs a `LineWriter` writing to the given sink.
    pub fn new(dst: W) -> LineWriter<W> {
        LineWriter { dst: dst }
    }

    /// Writes the given line to the destination sink.
    ///
    /// This specifically writes `line.text` followed by whatever byte sequence
    /// is indicated by the line's ending.
    pub fn write(&mut self, line: &Line) -> Result<()> {
        try!(self.dst.write_all(line.text));
        match line.ending {
            LineEnding::Nil => Ok(()),
            LineEnding::LF => self.dst.write_all("\n".as_bytes()),
            LineEnding::CRLF => self.dst.write_all("\r\n".as_bytes()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::MAX_LINE;

    fn reader_test(s: &str) -> LineReader<&[u8]> {
        let bytes = s.as_bytes();
        // Assert that the "copy LineReader to LineWriter" property holds.
        let mut written_bytes = Vec::new();
        {
            let mut reader = LineReader::new(bytes).unwrap();
            let mut writer = LineWriter::new(&mut written_bytes);

            loop {
                {
                    let line = reader.curr();
                    if LineClass::Eof == line.class {
                        break;
                    }
                    writer.write(&line).unwrap();
                }
                reader.read_next().unwrap();
            }
        }
        assert_eq!(bytes, &written_bytes[..]);

        LineReader::new(bytes).unwrap()
    }

    #[test]
    fn read_empty_file() {
        let file = "";
        let mut reader = reader_test(file);

        assert_eq!(LineClass::Eof, reader.curr().class);
        assert_eq!(LineEnding::Nil, reader.curr().ending);
        assert_eq!(0, reader.curr().text.len());

        reader.read_next().unwrap();
        assert_eq!(LineClass::Eof, reader.curr().class);
        assert_eq!(LineEnding::Nil, reader.curr().ending);
        assert_eq!(0, reader.curr().text.len());
    }

    #[test]
    fn read_file_without_line_ending() {
        let file = "foo";
        let mut reader = reader_test(file);

        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!(LineEnding::Nil, reader.curr().ending);
        assert_eq!(3, reader.curr().text.len());

        reader.read_next().unwrap();
        assert_eq!(LineClass::Eof, reader.curr().class);
        assert_eq!(LineEnding::Nil, reader.curr().ending);
        assert_eq!(0, reader.curr().text.len());
    }

    #[test]
    fn read_simple_mime_format() {
        let file = "From: jason@lin.gl\r\n\
                    Subject: Test\r\n\
                    \r\n\
                    From this line is not a terminator, since this is\
                    not a UNIX mbox file.\r\n\
                    -- \r\n";
        let mut reader = reader_test(file);

        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!(LineEnding::CRLF, reader.curr().ending);
        assert_eq!("From: jason@lin.gl".as_bytes(), reader.curr().text);

        reader.read_next().unwrap();
        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!(LineEnding::CRLF, reader.curr().ending);
        assert_eq!("Subject: Test".as_bytes(), reader.curr().text);

        reader.read_next().unwrap();
        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!(LineEnding::CRLF, reader.curr().ending);
        assert_eq!(0, reader.curr().text.len());

        reader.read_next().unwrap();
        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!(LineEnding::CRLF, reader.curr().ending);

        reader.read_next().unwrap();
        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!(LineEnding::CRLF, reader.curr().ending);
        assert_eq!("-- ".as_bytes(), reader.curr().text);

        reader.read_next().unwrap();
        assert_eq!(LineClass::Eof, reader.curr().class);
        assert_eq!(LineEnding::Nil, reader.curr().ending);
        assert_eq!(0, reader.curr().text.len());
    }

    #[test]
    fn read_unix_mbox() {
        let file = "From foo\n\
                    Subject: Blah\n\
                    From bar\n\
                    From\n\
                    Fromx\n";
        let mut reader = reader_test(file);

        assert_eq!(LineClass::MessageStart, reader.curr().class);
        assert_eq!(LineEnding::LF, reader.curr().ending);
        assert_eq!("From foo".as_bytes(), reader.curr().text);

        reader.read_next().unwrap();
        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!(LineEnding::LF, reader.curr().ending);
        assert_eq!("Subject: Blah".as_bytes(), reader.curr().text);

        reader.read_next().unwrap();
        assert_eq!(LineClass::MessageStart, reader.curr().class);
        assert_eq!(LineEnding::LF, reader.curr().ending);
        assert_eq!("From bar".as_bytes(), reader.curr().text);

        reader.read_next().unwrap();
        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!(LineEnding::LF, reader.curr().ending);
        assert_eq!("From".as_bytes(), reader.curr().text);

        reader.read_next().unwrap();
        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!(LineEnding::LF, reader.curr().ending);
        assert_eq!("Fromx".as_bytes(), reader.curr().text);

        reader.read_next().unwrap();
        assert_eq!(LineClass::Eof, reader.curr().class);
        assert_eq!(LineEnding::Nil, reader.curr().ending);
        assert_eq!(0, reader.curr().text.len());
    }

    #[test]
    fn read_multipart() {
        let file = "Not a delim, not at start of line: --DELIM\r\n\
                    --DELI Not a delimiter\r\n\
                    --DELIM\r\n\
                    --DELIM--\r\n\
                    --DELIM_RFC 2046 permits arbitrary garbage here\r\n\
                    --DELIM--plugh";
        let mut reader = reader_test(file);
        reader.set_multipart_delim(
            Some("DELIM".as_bytes().iter().cloned().collect()));

        assert_eq!(LineClass::Generic, reader.curr().class);

        reader.read_next().unwrap();
        assert_eq!(LineClass::Generic, reader.curr().class);

        reader.read_next().unwrap();
        assert_eq!(LineClass::MultipartDelim, reader.curr().class);

        reader.read_next().unwrap();
        assert_eq!(LineClass::MultipartEnd, reader.curr().class);

        reader.read_next().unwrap();
        assert_eq!(LineClass::MultipartDelim, reader.curr().class);

        reader.read_next().unwrap();
        assert_eq!(LineClass::MultipartEnd, reader.curr().class);
    }

    #[test]
    fn read_mixed_line_endings() {
        let file = "UNIX\n\
                    DOS\r\n\
                    Mac\r\
                    Bare";
        let mut reader = reader_test(file);

        assert_eq!(LineEnding::LF, reader.curr().ending);
        assert_eq!("UNIX".as_bytes(), reader.curr().text);
        reader.read_next().unwrap();

        assert_eq!(LineEnding::CRLF, reader.curr().ending);
        assert_eq!("DOS".as_bytes(), reader.curr().text);
        reader.read_next().unwrap();

        assert_eq!(LineEnding::Nil, reader.curr().ending);
        assert_eq!("Mac\rBare".as_bytes(), reader.curr().text);
        reader.read_next().unwrap();

        assert_eq!(LineClass::Eof, reader.curr().class);
    }

    #[test]
    fn read_extremely_long_line() {
        let mut file = String::with_capacity(MAX_LINE * 3 / 2);
        while file.len() <= MAX_LINE {
            file.push_str("From ");
        }
        file.push_str("\r\n");
        let mut reader = reader_test(&file);

        assert_eq!(LineEnding::Nil, reader.curr().ending);
        assert_eq!(LineClass::Truncated, reader.curr().class);
        reader.read_next().unwrap();

        assert_eq!(LineEnding::CRLF, reader.curr().ending);
        assert_eq!(LineClass::Truncated, reader.curr().class);
        reader.read_next().unwrap();

        assert_eq!(LineClass::Eof, reader.curr().class);
    }

    #[test]
    fn read_simple_header() {
        let file = "From: jason@lin.gl\r\nSubject: Test\n\n";
        let mut reader = reader_test(&file);
        let mut accum = Vec::new();

        {
            let (h,line) = reader.read_header(&mut accum).unwrap()
                .expect("No header found");
            assert_eq!(Headerness::Header, h);
            assert_eq!(LineClass::Generic, line.class);
            assert_eq!(LineEnding::CRLF, line.ending);
            assert_eq!("From: jason@lin.gl".as_bytes(), line.text);
        }

        {
            let (h,line) = reader.read_header(&mut accum).unwrap()
                .expect("No header found");
            assert_eq!(Headerness::Header, h);
            assert_eq!(LineClass::Generic, line.class);
            assert_eq!(LineEnding::LF, line.ending);
            assert_eq!("Subject: Test".as_bytes(), line.text);
        }

        assert_eq!(None, reader.read_header(&mut accum).unwrap());
        assert!(reader.curr().is_blank());

        reader.read_next().unwrap();
        assert_eq!(LineClass::Eof, reader.curr().class);
    }

    #[test]
    fn read_folded_header() {
        let file = "From mbox\n\
                    Subject: Foo\r\n\
                    \tBar\n\
                    To: nobody\n\
                    \x20 (plugh)\r\n\
                    X: Y\n\
                    From mbox\n\
                    Subject: Xyzzy\n\
                    \n\
                    \tOther text\n";
        let mut reader = reader_test(&file);
        let mut accum = Vec::new();

        assert_eq!(None, reader.read_header(&mut accum).unwrap());
        assert_eq!(LineClass::MessageStart, reader.curr().class);
        reader.read_next().unwrap();

        {
            let (h, line) = reader.read_header(&mut accum).unwrap()
                .expect("No header found");
            assert_eq!(Headerness::Header, h);
            assert_eq!(LineClass::Generic, line.class);
            assert_eq!(LineEnding::LF, line.ending);
            assert_eq!("Subject: Foo\r\n\tBar".as_bytes(), line.text);
        }

        {
            let (h, line) = reader.read_header(&mut accum).unwrap()
                .expect("No header found");
            assert_eq!(Headerness::Header, h);
            assert_eq!(LineClass::Generic, line.class);
            assert_eq!(LineEnding::CRLF, line.ending);
            assert_eq!("To: nobody\n  (plugh)".as_bytes(), line.text);
        }

        {
            let (h, line) = reader.read_header(&mut accum).unwrap()
                .expect("No header found");
            assert_eq!(Headerness::Header, h);
            assert_eq!(LineClass::Generic, line.class);
            assert_eq!(LineEnding::LF, line.ending);
            assert_eq!("X: Y".as_bytes(), line.text);
        }

        assert_eq!(None, reader.read_header(&mut accum).unwrap());
        assert_eq!(LineClass::MessageStart, reader.curr().class);
        reader.read_next().unwrap();

        {
            let (h, line) = reader.read_header(&mut accum).unwrap()
                .expect("No header found");
            assert_eq!(Headerness::Header, h);
            assert_eq!(LineClass::Generic, line.class);
            assert_eq!(LineEnding::LF, line.ending);
            assert_eq!("Subject: Xyzzy".as_bytes(), line.text);
        }

        assert_eq!(None, reader.read_header(&mut accum).unwrap());
        assert!(reader.curr().is_blank());
    }

    #[test]
    fn folded_headers_may_exceed_line_limit_by_one_line() {
        let mut six_hundred = String::with_capacity(600);
        for _ in 0..600 {
            six_hundred.push('x');
        }
        let mut file = String::with_capacity(1220);
        file.push_str(&six_hundred);
        file.push_str("\n\t");
        file.push_str(&six_hundred);
        file.push_str("\nFoo: Bar\n");

        let mut reader = reader_test(&file);
        let mut accum = Vec::new();

        {
            let (h, line) = reader.read_header(&mut accum).unwrap()
                .expect("No header found");
            assert_eq!(Headerness::Header, h);
            assert_eq!(1202, line.text.len());
        }

        {
            let (h, line) = reader.read_header(&mut accum).unwrap()
                .expect("No header found");
            assert_eq!(Headerness::Header, h);
            assert_eq!("Foo: Bar".as_bytes(), line.text);
        }
    }

    #[test]
    fn folded_headers_truncated_if_over_max_length() {
        let mut six_hundred = String::with_capacity(600);
        for _ in 0..600 {
            six_hundred.push('x');
        }
        let mut file = String::with_capacity(1220);
        file.push_str(&six_hundred);
        file.push_str("\n\t");
        file.push_str(&six_hundred);
        file.push_str("\n\tMore Text\n");

        let mut reader = reader_test(&file);
        let mut accum = Vec::new();

        {
            let (h, line) = reader.read_header(&mut accum).unwrap()
                .expect("No header found");
            assert_eq!(Headerness::RawLine, h);
            assert_eq!(1202, line.text.len());
        }

        assert_eq!(None, reader.read_header(&mut accum).unwrap());
        assert_eq!(LineClass::Generic, reader.curr().class);
        assert_eq!("\tMore Text".as_bytes(), reader.curr().text);
    }

    fn generic_line(s: &str) -> Line {
        Line {
            class: LineClass::Generic,
            ending: LineEnding::Nil,
            text: s.as_bytes(),
        }
    }

    #[test]
    fn split_header_well_formed() {
        let text = "Foo: Bär";
        let line = generic_line(text);

        let (name, value) = line.split_header()
            .expect("Failed to split header");
        assert_eq!("Foo", name);
        assert_eq!(" Bär".as_bytes(), value);
    }

    #[test]
    fn split_header_colon_at_beginning() {
        let text = ":foo: bar";
        let line = generic_line(text);

        assert_eq!(None, line.split_header());
    }

    #[test]
    fn split_header_space_in_name() {
        let text = "foo bar: baz";
        let line = generic_line(text);

        assert_eq!(None, line.split_header());
    }

    #[test]
    fn split_header_del_in_name() {
        let text = "foo\x7fbar: baz";
        let line = generic_line(text);

        assert_eq!(None, line.split_header());
    }
}