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

//! Implements actual encryption through GPG.

use std::io::{self,Read,Write};

use gpgme;

use pipe::Encrypt;

/// The GPG-based implementation of `pipe::Encrypt`.
#[derive(Debug)]
pub struct GpgEncrypt {
    ctx: gpgme::Context,
    keys: Vec<gpgme::keys::Key>,
}

impl GpgEncrypt {
    /// Creates a new `GpgEncrypt`.
    pub fn new(patterns: Vec<String>) -> gpgme::Result<GpgEncrypt> {
        let mut ctx = try!(gpgme::create_context());
        let patterns_len = patterns.len();
        let keys = {
            let mut it = try!(ctx.find_keys(patterns));
            let mut v = vec![];
            while let Some(k) = it.next() {
                v.push(try!(k));
            }
            v
        };

        // In the current published version of the gpgme bindings, we have no
        // way to get an error if any of the keys are invalid; instead, we just
        // get fewer of them.
        if keys.len() < patterns_len {
            return Err(gpgme::Error::new(gpgme::error::GPG_ERR_NOT_FOUND));
        }

        ctx.set_armor(true);

        let mut this = GpgEncrypt { ctx: ctx, keys: keys };
        // Test that encryption actually works and bail early if not.
        try!(this.encrypt_impl(&mut "foo".as_bytes(), &mut Vec::new()));

        Ok(this)
    }

    fn encrypt_impl<R : Read + Send, W : Write + Send>
        (&mut self, src: &mut R, dst: &mut W) -> gpgme::Result<()>
    {
        let flags = gpgme::ops::ENCRYPT_ALWAYS_TRUST;
        let res = unsafe {
            // `src` is borrowed till end of scope
            let mut src_data = try!(
                gpgme::Data::from_reader(static_reader(src))
                    .map_err(|err| err.error()));
            // `dst` is borrowed till end of scope
            let mut dst_data = try!(
                gpgme::Data::from_writer(static_writer(dst))
                    .map_err(|err| err.error()));
            try!(self.ctx.encrypt(
                &self.keys, flags, &mut src_data, &mut dst_data))
        };
        let mut iks = res.invalid_recipients();

        if let Some(ik) = iks.next() {
            let opt_reason = ik.reason();
            if let Some(ref reason) = opt_reason {
                panic!("Invalid recipient: {}: {}",
                       ik.fingerprint().unwrap_or("???"),
                       reason);
            } else {
                panic!("Invalid recipient: {}: unknown reason",
                       ik.fingerprint().unwrap_or("???"));
            }
        }

        Ok(())
    }
}

impl Encrypt for GpgEncrypt {
    fn encrypt<R : Read + Send, W : Write + Send>
        (&mut self, src: &mut R, dst: &mut W) -> io::Result<()>
    {
        self.encrypt_impl(src, dst).map_err(|err| {
            io::Error::new(io::ErrorKind::InvalidData, err)
        })
    }
}

///////////////////////////////////////////////////////////////////////////////
// For whatever reason, the GPGME bindings didn't bother to get lifetimes
// correct, and just declare everything 'static, even though the references to
// the readers and writers are strictly bound by the lifetime of the `Data`
// object.
//
// This whole mess is necessary to escape the lifetime check so we can use
// temporary objects instead.
struct ReadPtr {
    that: *mut (),
    f_read: unsafe fn (*mut (), &mut [u8]) -> io::Result<usize>,
}
unsafe impl Send for ReadPtr { }
impl Read for ReadPtr {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        unsafe {
            (self.f_read)(self.that, dst)
        }
    }
}
unsafe fn static_reader<R : Read + Send>(r: &mut R) -> ReadPtr {
    ReadPtr { that: r as *mut R as *mut (),
              f_read: read_callback::<R> }
}
unsafe fn read_callback<R : Read + Send>(
    that: *mut (), dst: &mut [u8]) -> io::Result<usize>
{
    (&mut*(that as *mut R)).read(dst)
}
struct WritePtr {
    that: *mut (),
    f_write: unsafe fn (*mut (), &[u8]) -> io::Result<usize>,
    f_flush: unsafe fn (*mut ()) -> io::Result<()>,
}
unsafe impl Send for WritePtr { }
impl Write for WritePtr {
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        unsafe {
            (self.f_write)(self.that, src)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        unsafe {
            (self.f_flush)(self.that)
        }
    }
}
unsafe fn static_writer<W : Write + Send>(w: &mut W) -> WritePtr {
    WritePtr { that: w as *mut W as *mut (),
               f_write: write_callback::<W>,
               f_flush: flush_callback::<W>, }
}
unsafe fn write_callback<W : Write + Send>(
    that: *mut (), src: &[u8]) -> io::Result<usize>
{
    (&mut*(that as *mut W)).write(src)
}
unsafe fn flush_callback<W : Write + Send>(that: *mut ()) -> io::Result<()> {
    (&mut*(that as *mut W)).flush()
}

// End of lifetime voodoo
///////////////////////////////////////////////////////////////////////////////
