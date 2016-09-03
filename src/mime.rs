//-
// Copyright (c) 2016, Jason Lingle
//
// This file is part of PGPipe.
//
// PGPipe is free software: you can  redistribute it and/or modify it under the
// terms of  the GNU General Public  License as published by  the Free Software
// Foundation, either version  3 of the License, or (at  your option) any later
// version.
//
// PGPipe is distributed  in the hope that  it will be useful,  but WITHOUT ANY
// WARRANTY; without  even the implied  warranty of MERCHANTABILITY  or FITNESS
// FOR  A PARTICULAR  PURPOSE.  See the  GNU General  Public  License for  more
// details.
//
// You should have received a copy of the GNU General Public License along with
// PGPipe. If not, see <http://www.gnu.org/licenses/>.

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

use std::ascii::AsciiExt;
use std::cmp::min;
use std::io::{BufRead,Read,Result,Write};
use std::iter::Peekable;
use std::mem;
use std::str;

/// The maximum line size before we split the line into smaller parts. (The
/// fact that there is no line ending between them is preserved).
const MAX_LINE : usize = 1024;
static CRLF : [u8;2] = [b'\r', b'\n'];

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

    /// Like `split_header`, but operates on a plain slice.
    pub fn split_header_slice(text: &[u8]) -> Option<(&str,&[u8])> {
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
            if colon >= text.len() {
                return None;
            }
            if b':' == text[colon] {
                break;
            }
            if text[colon] < 33 || text[colon] > 126 {
                return None;
            }
            colon += 1;
        }

        // field-name is invalid if empty
        if 0 == colon {
            return None;
        }

        return str::from_utf8(&text[0..colon]).ok().map(
            |name| (name, &text[colon + 1 ..]));
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
        Line::split_header_slice(self.text)
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
    /// The underlying binary writer.
    ///
    /// The `LineWriter` does not do any buffering itself, so it is reasonable
    /// to access this directly when emitting raw bytes is necessary.
    pub dst: W,
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

/// A deserialised representation of the Content-Type header. Only attributes
/// PGPipe actually cares about are included.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct ContentType {
    /// The top-level content type, eg, "multipart" or "text".
    pub toplevel: Vec<u8>,
    /// The content subtype, eg, "alternative" or "plain".
    pub subtype: Vec<u8>,
    /// If the Content-Type defines a "boundary" attribute, the value of that
    /// boundary.
    pub boundary: Option<Vec<u8>>,
}

impl ContentType {
    /// Returns whether this `ContentType` has a top-level type matching `tl`.
    pub fn is_toplevel_type(&self, tl: &str) -> bool {
        tl.as_bytes().eq_ignore_ascii_case(&self.toplevel)
    }

    /// Returns whether this `ContentType` has a subtype matching `st`.
    ///
    /// The actual subtype may be an X- prefix to `st`.
    pub fn is_subtype(&self, st: &str) -> bool {
        (st.as_bytes().eq_ignore_ascii_case(&self.subtype) ||
         (self.subtype.len() > 2 &&
          "x-".as_bytes().eq_ignore_ascii_case(&self.subtype[0..2]) &&
          st.as_bytes().eq_ignore_ascii_case(&self.subtype[2..])))
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum ContentTypeChar {
    Literal(u8),
    Delimiter,
    Slash, Semicolon, Equals,
    Nil,
}

/// An iterator which lexes the Content-Type header, as per [RFC 2045], which
/// of course us subtly different from the structured header syntax defined by
/// [RFC 822].
///
/// This lexer is generally permissive. It permits arbitrary binary data, and
/// ascribes no special meaning to the characters `<>@,[]?` which have no
/// meaning in the Content-Type header. It also permits mixing quoted strings
/// with tokens in the same word, or using multiple quoted strings in the same
/// word. Unclosed quotes, unclosed or unbalanced comments, and trailing
/// backslashes at the end of the string are silently ignored.
///
/// Handling of escaped CRLF-LWSP sequences is probably not correct, but they
/// are not useful within the Content-Type header anyway.
struct ContentTypeLexer<T : Iterator<Item = u8>> {
    src: T,
    comment_depth: u32,
    in_quote: bool,
    backslash: bool,
}

impl<T : Iterator<Item = u8>> Iterator for ContentTypeLexer<T> {
    type Item = ContentTypeChar;

    fn next(&mut self) -> Option<ContentTypeChar> {
        use self::ContentTypeChar::*;

        self.src.next().map(|ch| match ch {
            // [RFC 822] permits backslash escapes to occur within comments and
            // quoted-strings.
            _ if self.backslash => {
                self.backslash = false;
                if self.comment_depth > 0 {
                    // Backslash sequence in a comment suppresses any meaning
                    // for the following character, but we still don't want to
                    // emit it.
                    Nil
                } else {
                    Literal(ch)
                }
            },
            b'\\' => {
                self.backslash = true;
                Nil
            },

            // Quoted-strings also take effect in comments, yay
            b'"' => {
                self.in_quote = !self.in_quote;
                Nil
            },

            // [RFC 822] states that backslash quoting is required for CR
            // within a quoted-string, but doesn't really ascribe any meaning
            // to it not being backslash-quoted. Since folding is ordinarily
            // supposed to delete CR and LF, presumably that's the appropriate
            // thing here.
            b'\r' | b'\n' if self.in_quote => Nil,

            _  if self.in_quote => {
                if self.comment_depth > 0 {
                    // Quoted-string prevents interpretation of the comment
                    // characters, but we still don't want to emit the
                    // characters themselves.
                    Nil
                } else {
                    Literal(ch)
                }
            },

            // Comments nest and count as delimiters
            b'(' => {
                self.comment_depth += 1;
                Nil
            },
            b')' => {
                if self.comment_depth > 0 {
                    self.comment_depth -= 1;
                }
                Delimiter
            },
            _ if self.comment_depth > 0 => {
                Nil
            },

            // [RFC 2045] only ascribes meaning to '/', '=', and ';' beyond the
            // initial colon, besides the grammar common to all structured
            // headers.
            b'/' => Slash,
            b'=' => Equals,
            b';' => Semicolon,
            // We need to include CR and LF here since the unfolder does not
            // delete them.
            b' ' | b'\t' | b'\r' | b'\n' => Delimiter,
            // Anything else always stands for itself.
            _ => Literal(ch),
        })
    }
}

impl<T : Iterator<Item = u8>> ContentTypeLexer<T> {
    fn new(src: T) -> Self {
        ContentTypeLexer {
            src: src,
            comment_depth: 0,
            in_quote: false,
            backslash: false,
        }
    }
}

/// Parses a Content-Type header.
///
/// This parser is _extremely_ permissive, and accepts many things most parsers
/// wouldn't. If it successfully parses the Content-Type, at the very least it
/// is guaranteed that there is a non-empty toplevel type and subtype.
pub fn parse_content_type(data: &[u8]) -> Option<ContentType> {
    use self::ContentTypeChar::*;
    type CTC = ContentTypeChar;

    let mut it = ContentTypeLexer::new(data.iter().cloned())
        .filter(|ch| Nil != *ch)
        .peekable();

    fn skip_delims<T : Iterator<Item = CTC>>(it: &mut Peekable<T>) {
        while Some(&Delimiter) == it.peek() {
            it.next();
        }
    }

    fn skip_to<T : Iterator<Item = CTC>>(it: &mut Peekable<T>, ch: CTC) {
        while it.peek().map_or(false, |a| &ch != a) {
            it.next();
        }
        it.next();
    }

    fn read_word<T : Iterator<Item = CTC>>(it: &mut Peekable<T>) -> Vec<u8> {
        skip_delims(it);

        let mut dst = Vec::new();
        while let Some(&Literal(ch)) = it.peek() {
            dst.push(ch);
            it.next();
        }
        dst
    }

    let toplevel = read_word(&mut it);
    skip_to(&mut it, Slash);
    let subtype = read_word(&mut it);
    skip_to(&mut it, Semicolon);

    let mut boundary = None;

    while it.peek().is_some() {
        let attr = read_word(&mut it);
        skip_to(&mut it, Equals);
        let value = read_word(&mut it);
        skip_to(&mut it, Semicolon);

        if "boundary".as_bytes().eq_ignore_ascii_case(&attr) &&
            !value.is_empty()
        {
            boundary = Some(value);
        }
    }

    if !toplevel.is_empty() && !subtype.is_empty() {
        Some(ContentType {
            toplevel: toplevel,
            subtype: subtype,
            boundary: boundary,
        })
    } else {
        None
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum EntityStreamState {
    LineBody,
    LineEnding,
    Eof
}

/// Provides access as a byte stream to an entity / body part in a MIME
/// message.
///
/// The stream runs from the current line of the `LineReader` at the time the
/// stream is constructed up to but not including the first encountered line
/// whose class is greater than `Generic`. Whether the line ending preceding
/// that point is dependent on context. The terminating line is not consumed.
pub struct EntityStream<'a, T : BufRead + 'a> {
    src: &'a mut LineReader<T>,
    // The stream is implemented as a state machine, switching alternately
    // between yielding bytes from the line proper and the line ending.
    //
    // We start off in the `LineBody` state. When `line_off` passes the end of
    // the line body, the state switches to `LineEnding`. When the LineEdning
    // state is entered, we consume the current line from `src` and move onto
    // the next. `line_off` is reset to 0, and `ending_buf` set to the full
    // ending for the current line. Line ending switches back to `LineBody`
    // when its buffer becomes empty.
    //
    // Both state transitions can instead go to `Eof`; this happens for
    // `LineBody` if the terminating line is one which includes its _own_
    // newline as a prefix. `LineEnding` simply switches to `Eof` if the next
    // line is a terminator.
    //
    // Both the `LineBody` and `LineEnding` states may produce empty buffers;
    // thus, sometimes multiple state transitions are needed in sequence in
    // order to not have a premature EOF.
    state: EntityStreamState,
    line_off: usize,
    ending_buf: &'static [u8],
    // Track the previous line ending, so we can report it if we don't consume
    // it.
    prev_ending: LineEnding,
}

impl<'a, T : BufRead + 'a> EntityStream<'a, T> {
    pub fn new(src: &'a mut LineReader<T>) -> Self {
        let ending = src.curr().ending;
        let mut this = EntityStream {
            src: src,
            state: EntityStreamState::LineBody,
            line_off: 0,
            ending_buf: &CRLF,
            prev_ending: ending,
        };
        this.next_line();
        this
    }

    fn next_line(&mut self) {
        self.line_off = 0;
        self.ending_buf = match self.src.curr().ending {
            LineEnding::Nil => &CRLF[2..2],
            LineEnding::LF => &CRLF[1..2],
            LineEnding::CRLF => &CRLF[0..2],
        };
    }

    fn curr_buf(&self) -> &[u8] {
        match self.state {
            EntityStreamState::LineBody =>
                &self.src.curr().text[self.line_off..],
            EntityStreamState::LineEnding => self.ending_buf,
            EntityStreamState::Eof => &CRLF[0..0],
        }
    }

    fn need_next_buf(&self) -> bool {
        EntityStreamState::Eof != self.state && self.curr_buf().is_empty()
    }

    fn next_buf(&mut self) -> Result<()> {
        match self.state {
            EntityStreamState::LineBody => {
                self.prev_ending = self.src.curr().ending;
                try!(self.src.read_next());
                self.state = if self.unconsumed_line_ending().is_some() {
                    EntityStreamState::Eof
                } else {
                    EntityStreamState::LineEnding
                };
            },
            EntityStreamState::LineEnding => {
                self.next_line();
                self.state = if self.src.curr().class <= LineClass::Generic {
                    EntityStreamState::LineBody
                } else {
                    EntityStreamState::Eof
                };
            },
            EntityStreamState::Eof => panic!("Called next_buf() in EOF state"),
        }
        Ok(())
    }

    /// Returns the line ending that the stream did not consume, if any.
    pub fn unconsumed_line_ending(&self) -> Option<LineEnding> {
        match self.src.curr().class {
            // Multiparts and mbox messages include an extra newline
            // after the body they enclose.
            LineClass::MessageStart | LineClass::MultipartDelim |
            LineClass::MultipartEnd => Some(self.prev_ending),
            LineClass::Eof if self.src.mbox => Some(self.prev_ending),
            _ => None,
        }
    }
}

impl<'a, T : BufRead + 'a> Read for EntityStream<'a, T> {
    fn read(&mut self, dst: &mut [u8]) -> Result<usize> {
        let len = {
            let src = try!(self.fill_buf());
            let len = min(dst.len(), src.len());
            dst[0..len].clone_from_slice(&src[0..len]);
            len
        };
        self.consume(len);
        Ok(len)
    }
}

impl<'a, T : BufRead + 'a> BufRead for EntityStream<'a, T> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        while self.need_next_buf() {
            try!(self.next_buf());
        }
        Ok(self.curr_buf())
    }

    fn consume(&mut self, amt: usize) {
        match self.state {
            EntityStreamState::LineBody =>
                self.line_off += amt,
            EntityStreamState::LineEnding =>
                self.ending_buf = &self.ending_buf[amt..],
            EntityStreamState::Eof => assert_eq!(0, amt),
        }
    }
}

#[cfg(test)]
mod test {
    use std::io;

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

    fn parse_ct(str: &str) -> ContentType {
        parse_content_type(str.as_bytes()).expect("Failed to parse")
    }

    #[test]
    fn parse_simple_content_type() {
        let ct = parse_ct("text/plain");

        assert_eq!("text".as_bytes(), &ct.toplevel[..]);
        assert_eq!("plain".as_bytes(), &ct.subtype[..]);
        assert!(ct.boundary.is_none());
    }

    #[test]
    fn parse_simple_content_type_with_boundary() {
        let ct = parse_ct("multipart/alternative; boundary=foo");

        assert_eq!("multipart".as_bytes(), &ct.toplevel[..]);
        assert_eq!("alternative".as_bytes(), &ct.subtype[..]);
        assert_eq!("foo".as_bytes(), &ct.boundary.unwrap()[..]);
    }

    fn parse_with_boundary(expected_toplevel: &str,
                           expected_subtype: &str,
                           expected_boundary: &str,
                           s: &str) {
        let ct = parse_ct(s);
        assert_eq!(expected_toplevel.as_bytes(), &ct.toplevel[..]);
        assert_eq!(expected_subtype.as_bytes(), &ct.subtype[..]);
        assert_eq!(expected_boundary.as_bytes(), &ct.boundary.unwrap()[..]);
    }

    #[test]
    fn extraneous_space_supported_in_content_type() {
        parse_with_boundary(
            "a", "b", "foo", "a / b ; boundary = \t\r\nfoo");
    }

    #[test]
    fn last_boundary_in_content_type_wins() {
        parse_with_boundary(
            "a", "b", "foo", "a/b; bonudary=bar; boundary=foo");
    }

    #[test]
    fn comments_in_content_type_ignored() {
        parse_with_boundary(
            "a", "b", "foo", "a/b; boundary=foo; (boundary=bar)");
    }

    #[test]
    fn content_type_quoting_supported() {
        parse_with_boundary(
            "a", "b", "foo:bar", "a/b; \"boundary\" = \"foo:bar\"");
    }

    #[test]
    fn content_type_escapes_in_quotes_supported() {
        parse_with_boundary(
            "a", "b", "\"\\", "a/b; boundary=\"\\\"\\\\\"");
    }

    #[test]
    fn content_type_escapes_and_quotes_in_comments_supported() {
        parse_with_boundary(
            "a", "b", "foo", "a/b; (\"(\\\"(\"\\() boundary=foo");
    }

    #[test]
    fn content_type_unclosed_comment_ignored() {
        parse_with_boundary(
            "a", "b", "foo", "a/b; boundary=foo (");
    }

    #[test]
    fn content_type_unbalanced_close_paren_ignored() {
        parse_with_boundary(
            "a", "b", "foo", "a)/b);boundary=foo)");
    }

    #[test]
    fn content_type_unclosed_quote_tolerated() {
        parse_with_boundary(
            "a", "b", "foo", "a/b; boundary=\"foo");
    }

    #[test]
    fn content_type_bs_at_end_ignored() {
        parse_with_boundary(
            "a", "b", "foo", "a/b; boundary=foo\\");
    }

    #[test]
    fn content_type_other_things_ignored() {
        parse_with_boundary(
            "a", "b", "foo", "a/b; boundary=foo; plugh=xyzzy; ;/=?[]@");
    }

    #[test]
    fn content_type_rejected_if_no_slash() {
        assert!(parse_content_type("text plain".as_bytes()).is_none());
    }

    #[test]
    fn content_type_rejected_if_subtype_empty() {
        assert!(parse_content_type("text/".as_bytes()).is_none());
    }

    #[test]
    fn content_type_rejected_if_toplevel_type_empty() {
        assert!(parse_content_type("/foo".as_bytes()).is_none());
    }

    #[test]
    fn content_type_simple_type_tests() {
        let ct = parse_ct("TeXt/PlAiN");
        assert!(ct.is_toplevel_type("text"));
        assert!(!ct.is_toplevel_type("tex"));
        assert!(!ct.is_toplevel_type("texts"));
        assert!(ct.is_subtype("plain"));
        assert!(!ct.is_subtype("plai"));
        assert!(!ct.is_subtype("plains"));
    }

    #[test]
    fn content_type_x_prefix_permitted_on_subtype() {
        let ct = parse_ct("FoO/X-PlUgh");
        assert!(ct.is_subtype("x-plugh"));
        assert!(ct.is_subtype("plugh"));
    }

    fn copy_entity_stream<T : io::BufRead>(rd: &mut EntityStream<T>)
                                           -> Vec<u8> {
        let mut out = Vec::new();
        io::copy(rd, &mut out).unwrap();
        out
    }

    #[test]
    fn entity_stream_to_eof() {
        let file = "foo\r\n\
                    bar\n\
                    baz";
        let mut reader = reader_test(file);
        {
            let mut entity = EntityStream::new(&mut reader);
            let copied = copy_entity_stream(&mut entity);

            assert_eq!(file.as_bytes(), &copied[..]);
            assert_eq!(None, entity.unconsumed_line_ending());
        }
        assert_eq!(LineClass::Eof, reader.curr().class);
    }

    #[test]
    fn entity_stream_to_multipart_no_nl() {
        let file = "foo\r\n\
                    bar\r\n\
                    --DELIM--";
        let mut reader = reader_test(file);
        reader.set_multipart_delim(
            Some("DELIM".as_bytes().iter().cloned().collect()));
        {
            let mut entity = EntityStream::new(&mut reader);
            let copied = copy_entity_stream(&mut entity);

            assert_eq!("foo\r\nbar".as_bytes(), &copied[..]);
            assert_eq!(Some(LineEnding::CRLF),
                       entity.unconsumed_line_ending());
        }
        assert_eq!(LineClass::MultipartEnd, reader.curr().class);
    }

    #[test]
    fn entity_stream_to_multipart_with_nl() {
        let file = "foo\r\n\
                    bar\r\n\
                    \n\
                    --DELIM--";
        let mut reader = reader_test(file);
        reader.set_multipart_delim(
            Some("DELIM".as_bytes().iter().cloned().collect()));
        {
            let mut entity = EntityStream::new(&mut reader);
            let copied = copy_entity_stream(&mut entity);

            assert_eq!("foo\r\nbar\r\n".as_bytes(), &copied[..]);
            assert_eq!(Some(LineEnding::LF),
                       entity.unconsumed_line_ending());
        }
        assert_eq!(LineClass::MultipartEnd, reader.curr().class);
    }

    #[test]
    fn entity_stream_to_eof_mbox() {
        let file = "From foo\n\
                    foo\n";
        let mut reader = reader_test(file);
        reader.read_next().unwrap();
        {
            let mut entity = EntityStream::new(&mut reader);
            let copied = copy_entity_stream(&mut entity);

            assert_eq!("foo".as_bytes(), &copied[..]);
            assert_eq!(Some(LineEnding::LF),
                       entity.unconsumed_line_ending());
        }
        assert_eq!(LineClass::Eof, reader.curr().class);
    }

    #[test]
    fn entity_stream_to_next_message_mbox() {
        let file = "From foo\n\
                    foo\n\
                    From bar\n\
                    bar\n";
        let mut reader = reader_test(file);
        reader.read_next().unwrap();
        {
            let mut entity = EntityStream::new(&mut reader);
            let copied = copy_entity_stream(&mut entity);

            assert_eq!("foo".as_bytes(), &copied[..]);
            assert_eq!(Some(LineEnding::LF),
                       entity.unconsumed_line_ending());
        }
        assert_eq!(LineClass::MessageStart, reader.curr().class);
    }
}
