PGPipe
======

Introduction
------------

PGPipe is a small utility built on GPG which can transparently add PGP/MIME
encryption to messages which do not have it. While this obviously does not have
the usual PGP/MIME benefit of securing the messages against interception, it
still provides a convenient way to ensure that (most of) your messages are not
stored on the server in cleartext, but rather only decrypted in your mail
client's memory.

There are two target use-cases for PGPipe:

- Encrypting new email as it arrives.

- Encrypting the messages in a UNIX mbox file, specifically one managed by
  [UW-IMAP](http://www.washington.edu/imap/).

PGPipe has not been tested for compatibility with any client software other
than Thunderbird + Enigmail. It probably works elsewhere, though.

Basic Setup
-----------

These instructions are for FreeBSD; with light adaptation they should also work
elsewhere.

To build PGPipe, you need Rust 1.7.0 or later, Cargo, and the gpgme library.
```
# pkg install rust cargo gpgme
```
Then you can test and build PGPipe:
```
$ cargo test
$ cargo build --release
```

This produces a static binary in `target/release/pgpipe`. This can be copied to
other systems of the same platform and should be expected to work as long as
`gpgme` is installed there (`rust` and `cargo` are not needed for deployment).

In order to accomplish anything useful here, you need to have a GPG key pair or
your client systems and must put the _public key_ on anything that will be
encrypting mail on your behalf. A tutorial on using GPG is beyond the scope of
this README; there are plenty of resources elsewhere.

If you already have a GPG key pair locally and know its fingerprint, the
easiest way to get it onto the server (if you're going down the
encrypt-incoming-mail route) is
```
$ gpg --export -a YOURFINGERPRINT | ssh you@yourserver 'gpg --import'
```
Note that you do not need to mark the key as trusted for use with PGPipe; it
will work with any key regardless of trust level.

Encrypting a UNIX mbox
----------------------

These instructions have only been tested against UW-IMAP, though they probably
also work with Panda IMAP and most other things that use the mbox format.

First, make sure the mailbox is actually in mbox format. Mbox mailboxes are
flat files starting with `From ` (note the space). With UW-IMAP, you can
convert if needed with a command like
```
$ mailutil copy some-folder \#driver.unix/some-folder-mbox
```
and then use `some-folder-mbox` instead.

Outright overwriting a folder doesn't play well with most mail clients; it's
best to create a new folder to hold the result. You can do this from your mail
client, or for UW-IMAP via the command-line with
```
$ mailutil create \#driver.unix/encrypted-folder-name
```

You can now do the encryption with
```
$ pgpipe FINGERPRINT ... <some-folder-mbox >encrypted-folder-name
```

PGPipe knows about the special message UW-IMAP inserts at the top of the
mailbox and leaves it alone.

Once that completes, verify the new folder actually works, remove the old
folder(s) and rename the new one as you please (or convert to a better format,
like mbx).

Encrypting Incoming Mail
------------------------

The script [pgpipe-dmail](pgpipe-dmail) can be used in your `~/.forward` to
encrypt everything incoming. The documentation in the script has instructions
on how to use it.

Note that this has only been tested with OpenSMTPD, and dmail is somewhat
UW-IMAP-specific, so adaptation is almost certainly needed for this to work on
other systems.

You almost certainly want to set up a fallback mail delivery mechanism in case
something breaks.

What Does and Does _Not_ Get Encrypted
--------------------------------------

Since PGPipe conforms to the PGP/MIME standard, it inherits the same
limitations. Most notably, all top-level headers remain in cleartext, so the
subject, sender, receivers, etc is not encrypted.

PGPipe recognises existing PGP/MIME, S/MIME, and `application/pgp` messages and
leaves them alone. This does mean that if they were _signed_, but not
_encrypted_, they remain cleartext.

By default, PGPipe encrypts the whole top-level message body, which is what
Enigmail seems to expect. The `-R` flag enables an alternate interpretation of
the standard which encrypts every child body part separately. This is known to
break Enigmail. If there are any supporting clients, this does have the benefit
that one doesn't need to download and decrypt all the attachments on a message
just to read its text body.

If a message has unacceptably large content headers (thousands of characters
wide) or too many content headers (hundreds), PGPipe will not encrypt the
message so that it does not get damaged.

License
-------

[GPLv3 or later](COPYING)
