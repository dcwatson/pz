//! Implementation of the [PZip format](https://github.com/imsweb/pzip) in Rust.
//!
//! Streaming example:
//!
//! ```
//! use std::io;
//! use pzip::{PZip, Password, Algorithm, Compression, Error, PZipKey};
//!
//! fn main() -> Result<(), Error> {
//!     let plaintext = b"hello world";
//!     let mut ciphertext = Vec::<u8>::new();
//!     let mut check = Vec::<u8>::new();
//!     let key = Password("pzip");
//!     PZip::encrypt_to(
//!         &mut io::Cursor::new(plaintext),
//!         &mut ciphertext,
//!         Algorithm::AesGcm256,
//!         &key,
//!         Compression::None,
//!     )?;
//!     PZip::decrypt_to(
//!         &mut io::Cursor::new(ciphertext),
//!         &mut check,
//!         key.material()
//!     )?;
//!     assert_eq!(check, plaintext);
//!     Ok(())
//! }
//! ```
//!
//! One-shot example:
//!
//! ```
//! use pzip::{PZip, Password, Algorithm, Compression, Error, PZipKey};
//!
//! fn main() -> Result<(), Error> {
//!     let key = Password("secret");
//!     let plaintext = b"hello world";
//!     let ciphertext = PZip::encrypt(
//!         plaintext,
//!         Algorithm::AesGcm256,
//!         &key,
//!         Compression::None
//!     )?;
//!     let check = PZip::decrypt(&ciphertext, key.material())?;
//!     assert_eq!(check, plaintext);
//!     Ok(())
//! }
//! ```

use libdeflater::{CompressionLvl, Compressor, Decompressor};
use ring::{
    aead, error::Unspecified, hkdf, hkdf::KeyType, pbkdf2, rand, rand::SecureRandom,
};
use std::cmp;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::io::Write;
use std::num::NonZeroU32;

/// The multitude of ways this crate can fail.
#[derive(Debug)]
pub enum Error {
    /// Wrapper for `io::Error` when reading/writing.
    IoError(io::Error),
    /// Returned when the first two bytes of a PZip file are not `\xB6\x9E`.
    IncorrectMagic([u8; 2]),
    /// RAn unknown version is specified (currently only version 1 is available).
    UnknownVersion(u8),
    /// An unknown [`Algorithm`](enum.Algorithm.html) was specified.
    UnknownAlgorithm(u8),
    /// An unknown [`KeyDerivation`](enum.KeyDerivation.html) was specified.
    UnknownKeyDerivation(u8),
    /// An unknown [`Compression`](enum.Compression.html) was specified.
    UnknownCompression(u8),
    /// An unknown [`Tag`](enum.Tag.html) was specified.
    UnknownTag(u8),
    /// The specified key was an incorrect length for the
    /// [`Algorithm`](enum.Algorithm.html).
    InvalidKeySize(u8),
    /// The specified nonce was not 12 bytes.
    InvalidNonceSize(usize),
    /// PBKDF2 iterations must be greater than 0.
    InvalidIterations(u32),
    /// An integer [`Tag`](enum.Tag.html) had a length besides 1, 2, 4, or 8.
    InvalidIntegerTagSize(usize),
    /// Returned when encryption/decryption counter reaches `u32::MAX`.
    NonceExhaustion,
    /// Returned when trying to read a block while at EOF.
    NoMoreBlocks,
    /// Wrapper for `ring::error::Unspecified`.
    CryptoError(Unspecified),
    /// libdeflater compression error.
    CompressionError(libdeflater::CompressionError),
    /// libdeflater decompression error.
    DecompressionError(libdeflater::DecompressionError),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<libdeflater::CompressionError> for Error {
    fn from(error: libdeflater::CompressionError) -> Self {
        Error::CompressionError(error)
    }
}

impl From<libdeflater::DecompressionError> for Error {
    fn from(error: libdeflater::DecompressionError) -> Self {
        Error::DecompressionError(error)
    }
}

impl From<Unspecified> for Error {
    fn from(error: Unspecified) -> Self {
        Error::CryptoError(error)
    }
}

/// The default block size to use when writing PZip blocks.
pub const DEFAULT_BLOCK_SIZE: usize = 262144;

/// The default number of iterations to use in PBKDF2 derivations.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 200000;

/// Tagged data used for encryption, key derivation, or file metadata.
///
/// Each PZip archive may have some number (usually non-zero) of tagged data elements
/// that specify parameters required for encryption (`Nonce`), key derivation
/// (`Salt`, `Iterations`, `Info`), or file metadata (`Filename`, `Mimetype`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Tag {
    Nonce = 1,
    Salt = 2,
    Iterations = -3,
    Info = 4,
    Filename = 5,
    Application = 6,
    Mimetype = 7,
    Comment = 127,
}

impl Tag {
    /// Returns a `Tag` for the specified `u8` if known, otherwise
    /// [`Error::UnknownTag`].
    ///
    /// [`Error::UnknownTag`]: enum.Error.html#variant.UnknownTag
    pub fn from(num: u8) -> Result<Tag, Error> {
        Ok(match num {
            1 => Tag::Nonce,
            2 => Tag::Salt,
            253 => Tag::Iterations, // -3
            4 => Tag::Info,
            5 => Tag::Filename,
            6 => Tag::Application,
            7 => Tag::Mimetype,
            127 => Tag::Comment,
            _ => return Err(Error::UnknownTag(num)),
        })
    }
}

pub type PZipTags = HashMap<Tag, Vec<u8>>;

/// Given a "base" nonce and a counter, returns a [`Nonce`] suitable for
/// encrypting/decrypting one block.
///
/// Nonces are generated by XOR-ing the last 4 bytes of the base nonce with a 32-bit
/// big-endian representation of the counter. Since Ring currently only supports 96-bit
/// nonces, this method will return [`Error::InvalidNonceSize`] if the base nonce is not
/// 12 bytes long. [`Error::NonceExhaustion`] is returned if counter is `u32::MAX`.
///
/// [`Nonce`]: ../ring/aead/struct.Nonce.html
/// [`Error::InvalidNonceSize`]: enum.Error.html#variant.InvalidNonceSize
/// [`Error::NonceExhaustion`]: enum.Error.html#variant.NonceExhaustion
pub fn derive_nonce(base: &[u8], counter: u32) -> Result<aead::Nonce, Error> {
    if counter == u32::MAX {
        return Err(Error::NonceExhaustion);
    }

    if base.len() != 12 {
        // Ring only allows 96-bit nonces.
        return Err(Error::InvalidNonceSize(base.len()));
    }

    let mut next = [0u8; 12];
    next.copy_from_slice(&base);
    let ctr = counter.to_be_bytes();
    let i = next.len() - 4;
    next[i] ^= ctr[0];
    next[i + 1] ^= ctr[1];
    next[i + 2] ^= ctr[2];
    next[i + 3] ^= ctr[3];

    Ok(aead::Nonce::assume_unique_for_key(next))
}

fn read_int(bytes: &[u8]) -> Result<u64, Error> {
    Ok(match bytes.len() {
        1 => bytes[0] as u64,
        2 => u16::from_be_bytes(bytes[0..2].try_into().unwrap()) as u64,
        4 => u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as u64,
        8 => u64::from_be_bytes(bytes[0..8].try_into().unwrap()) as u64,
        n => return Err(Error::InvalidIntegerTagSize(n)),
    })
}

/// The encryption algorithms known by PZip.
///
/// Encapsulates the enryption, decryption, key wrapping, and tags required for each
/// algorithm.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    AesGcm256 = 1,
}

impl Algorithm {
    /// Returns an `Algorithm` for the specified `u8` if known, otherwise
    /// [`Error::UnknownAlgorithm`].
    ///
    /// [`Error::UnknownAlgorithm`]: enum.Error.html#variant.UnknownAlgorithm
    pub fn from(num: u8) -> Result<Algorithm, Error> {
        Ok(match num {
            1 => Algorithm::AesGcm256,
            _ => return Err(Error::UnknownAlgorithm(num)),
        })
    }

    /// Returns the [`PZipTags`](type.PZipTags.html) to be used for new PZip files using
    /// this algorithm.
    ///
    /// Generally, this should return suitable random defaults for any encryption
    /// parameters. Specifically, for AES-GCM, this returns a
    /// [`Tag::Nonce`](enum.Tag.html#variant.Nonce) with 12 random bytes.
    pub fn tags(&self) -> PZipTags {
        match *self {
            Algorithm::AesGcm256 => {
                let rng = rand::SystemRandom::new();
                let mut nonce = vec![0u8; 12];
                rng.fill(&mut nonce).ok();
                let mut tags = PZipTags::with_capacity(1);
                tags.entry(Tag::Nonce).or_insert(nonce);
                tags
            }
        }
    }

    /// Wraps the (either raw or already-derived) key bytes into a [`LessSafeKey`] than
    /// can be used for encryption and decryption with this algorithm.
    ///
    /// [`LessSafeKey`]: ../ring/aead/struct.LessSafeKey.html
    pub fn wrap_key(&self, key_bytes: &[u8]) -> Result<aead::LessSafeKey, Error> {
        match *self {
            Algorithm::AesGcm256 => {
                let raw = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)?;
                Ok(aead::LessSafeKey::new(raw))
            }
        }
    }

    /// Encrypts a block of data.
    pub fn encrypt(
        &self,
        key: &aead::LessSafeKey,
        data: &[u8],
        tags: &PZipTags,
        counter: u32,
    ) -> Result<Vec<u8>, Error> {
        match *self {
            Algorithm::AesGcm256 => {
                let base = tags.get(&Tag::Nonce).expect("missing nonce");
                let nonce = derive_nonce(&base, counter)?;
                let mut sealed = data.to_vec();
                key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut sealed)?;
                Ok(sealed)
            }
        }
    }

    /// Decrypts a block of data.
    pub fn decrypt(
        &self,
        key: &aead::LessSafeKey,
        data: &[u8],
        tags: &PZipTags,
        counter: u32,
    ) -> Result<Vec<u8>, Error> {
        match *self {
            Algorithm::AesGcm256 => {
                let base = tags.get(&Tag::Nonce).expect("missing nonce");
                let nonce = derive_nonce(&base, counter)?;
                let mut plaintext = data.to_vec();
                key.open_in_place(nonce, aead::Aad::empty(), &mut plaintext)?;
                let size = plaintext.len() - 16;
                plaintext.truncate(size);
                Ok(plaintext)
            }
        }
    }
}

impl KeyType for Algorithm {
    fn len(&self) -> usize {
        match *self {
            Algorithm::AesGcm256 => 32,
        }
    }
}

/// The key derivation functions (KDFs) known by PZip.
///
/// Encapsulates the tags needed for each KDF along with a common [`derive`] method.
///
/// [`derive`]: enum.KeyDerivation.html#method.derive
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyDerivation {
    Raw = 0,
    HkdfSha256 = 1,
    Pbkdf2Sha256 = 2,
}

impl KeyDerivation {
    /// Returns a `KeyDerivation` for the specified `u8` if known, otherwise
    /// [`Error::UnknownKeyDerivation`].
    ///
    /// [`Error::UnknownKeyDerivation`]: enum.Error.html#variant.UnknownKeyDerivation
    pub fn from(num: u8) -> Result<KeyDerivation, Error> {
        Ok(match num {
            0 => KeyDerivation::Raw,
            1 => KeyDerivation::HkdfSha256,
            2 => KeyDerivation::Pbkdf2Sha256,
            _ => return Err(Error::UnknownKeyDerivation(num)),
        })
    }

    /// Returns the [`PZipTags`](type.PZipTags.html) to be used for new PZip files using
    /// this key derivation.
    ///
    /// Generally, this should return suitable random defaults for any derivation
    /// parameters. Specifically, for HKDF, this returns a
    /// [`Tag::Salt`](enum.Tag.html#variant.Salt) with a number of random bytes equal to
    /// the hash length. For PBKDF2, this returns a similar
    /// [`Tag::Salt`](enum.Tag.html#variant.Salt) as well as a
    /// [`Tag::Iterations`](enum.Tag.html#variant.Iterations) specifying the number of
    /// PBKDF2 rounds.
    pub fn tags(&self) -> PZipTags {
        let rng = rand::SystemRandom::new();
        match *self {
            KeyDerivation::Raw => PZipTags::new(),
            KeyDerivation::HkdfSha256 => {
                let mut salt = vec![0u8; 32];
                rng.fill(&mut salt).ok();
                let mut tags = PZipTags::with_capacity(1);
                tags.entry(Tag::Salt).or_insert(salt);
                tags
            }
            KeyDerivation::Pbkdf2Sha256 => {
                let mut salt = vec![0u8; 32];
                rng.fill(&mut salt).ok();
                let mut tags = PZipTags::with_capacity(2);
                let iter_bytes = DEFAULT_PBKDF2_ITERATIONS.to_be_bytes().to_vec();
                tags.entry(Tag::Iterations).or_insert(iter_bytes);
                tags.entry(Tag::Salt).or_insert(salt);
                tags
            }
        }
    }

    /// Derives key bytes from input key material for the specified
    /// [`Algorithm`](enum.Algorithm.html), using parameters found in `tags`.
    ///
    /// The number of bytes returned depends on the length of the key expected by the
    /// algorithm.
    pub fn derive(
        &self,
        material: &[u8],
        algorithm: Algorithm,
        tags: &PZipTags,
    ) -> Result<Vec<u8>, Error> {
        Ok(match *self {
            KeyDerivation::Raw => material.to_vec(),
            KeyDerivation::HkdfSha256 => {
                let salt = tags.get(&Tag::Salt).expect("missing salt");
                let mut key_bytes = vec![0u8; algorithm.len()];
                hkdf::Salt::new(hkdf::HKDF_SHA256, &salt)
                    .extract(&material)
                    .expand(&[], algorithm)?
                    .fill(&mut key_bytes)?;
                key_bytes
            }
            KeyDerivation::Pbkdf2Sha256 => {
                let iter_bytes =
                    tags.get(&Tag::Iterations).expect("missing iterations");
                let salt = tags.get(&Tag::Salt).expect("missing salt");
                let iterations = read_int(&iter_bytes).expect("bad int size");
                let mut key_bytes = vec![0u8; algorithm.len()];
                pbkdf2::derive(
                    pbkdf2::PBKDF2_HMAC_SHA256,
                    NonZeroU32::new(iterations as u32).unwrap(),
                    &salt,
                    &material,
                    &mut key_bytes,
                );
                key_bytes
            }
        })
    }
}

/// Wraps a [`KeyDerivation`](enum.KeyDerivation.html) and input key material.
pub trait PZipKey {
    fn kdf(&self) -> KeyDerivation;
    fn material(&self) -> &[u8];
    fn tags(&self) -> PZipTags {
        self.kdf().tags()
    }
}

/// A raw key (no derivation) for encryption and decryption. Must match the expected key
/// size of the [`Algorithm`] being used.
///
/// [`Algorithm`]: enum.Algorithm.html
pub struct RawKey<'a>(pub &'a [u8]);

impl PZipKey for RawKey<'_> {
    fn kdf(&self) -> KeyDerivation {
        KeyDerivation::Raw
    }

    fn material(&self) -> &[u8] {
        &self.0
    }
}

/// A password that will be encoded as UTF-8 and derived with PBKDF2-SHA256.
pub struct Password<'a>(pub &'a str);

impl PZipKey for Password<'_> {
    fn kdf(&self) -> KeyDerivation {
        KeyDerivation::Pbkdf2Sha256
    }

    fn material(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A key of any length (longer is better) that will be derived with HKDF-SHA256.
pub struct Key<'a>(pub &'a [u8]);

impl PZipKey for Key<'_> {
    fn kdf(&self) -> KeyDerivation {
        KeyDerivation::HkdfSha256
    }

    fn material(&self) -> &[u8] {
        &self.0
    }
}

/// The compression methods known by PZip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Compression {
    None = 0,
    Gzip = 1,
}

impl Compression {
    /// Returns a `Compression` for the specified `u8` if known, otherwise
    /// [`Error::UnknownCompression`].
    ///
    /// [`Error::UnknownCompression`]: enum.Error.html#variant.UnknownCompression
    pub fn from(num: u8) -> Result<Compression, Error> {
        Ok(match num {
            0 => Compression::None,
            1 => Compression::Gzip,
            _ => return Err(Error::UnknownCompression(num)),
        })
    }

    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(match *self {
            Compression::None => data.to_vec(),
            Compression::Gzip => {
                let mut gz = Compressor::new(CompressionLvl::default());
                let max_size = gz.gzip_compress_bound(data.len());
                let mut compressed = vec![0u8; max_size];
                let actual = gz.gzip_compress(data, &mut compressed)?;
                compressed.truncate(actual);
                compressed
            }
        })
    }

    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(match *self {
            Compression::None => data.to_vec(),
            Compression::Gzip => {
                let mut gz = Decompressor::new();
                // Read the gzip original data size to figure out how much to allocate.
                let n = data.len() - 4;
                let orig_size = u16::from_le_bytes(data[n..n + 2].try_into().unwrap());
                let mut decompressed = vec![0u8; orig_size as usize];
                gz.gzip_decompress(data, &mut decompressed)?;
                decompressed
            }
        })
    }
}

/// Structure for holding information about a PZip archive, and a namespace for common
/// operations.
#[allow(dead_code)]
pub struct PZip {
    version: u8,
    flags: u8,
    algorithm: Algorithm,
    kdf: KeyDerivation,
    compression: Compression,
    tags: PZipTags,
    key: aead::LessSafeKey,
}

impl PZip {
    /// Returns a [`PZipReader`] after reading the PZip header and tag data.
    ///
    /// This method first reads the PZip header and does some validation. So in addition
    /// to [`Error::IoError`] caused by read failures, it may also return
    /// [`Error::IncorrectMagic`] if the file magic is incorrect, or
    /// [`Error::UnknownVersion`] if an unknown version is specified. Any of the other
    /// `Unknown*` errors may also be returned when trying to parse the algorithm, KDF,
    /// compression method, or tags.
    ///
    /// [`PZipReader`]: struct.PZipReader.html
    /// [`Error::IoError`]: enum.Error.html#variant.IoError
    /// [`Error::IncorrectMagic`]: enum.Error.html#variant.IncorrectMagic
    /// [`Error::UnknownVersion`]: enum.Error.html#variant.UnknownVersion
    pub fn reader<'r, T: io::Read>(
        reader: &'r mut T,
        key_material: &[u8],
    ) -> Result<PZipReader<'r, T>, Error> {
        let mut header = [0u8; 8];
        reader.read_exact(&mut header)?;

        if header[0] != 0xB6 || header[1] != 0x9E {
            return Err(Error::IncorrectMagic([header[0], header[1]]));
        }

        if header[2] != 1 {
            return Err(Error::UnknownVersion(header[2]));
        }

        let alg = Algorithm::from(header[4])?;
        let kdf = KeyDerivation::from(header[5])?;
        let compression = Compression::from(header[6])?;

        let mut tag_header = [0u8; 2];
        let mut tags = PZipTags::new();
        for _ in 0..header[7] {
            reader.read_exact(&mut tag_header)?;
            let tag = Tag::from(tag_header[0])?; // Should probably just ignore/log this
            let mut tag_data = vec![0u8; tag_header[1] as usize];
            reader.read_exact(&mut tag_data)?;
            tags.entry(tag).or_insert(tag_data);
        }

        let key_bytes = kdf.derive(&key_material, alg, &tags)?;
        let key = alg.wrap_key(&key_bytes)?;

        return Ok(PZipReader {
            pzip: PZip {
                version: header[2],
                flags: header[3],
                algorithm: alg,
                kdf: kdf,
                compression: compression,
                tags: tags,
                key: key,
            },
            reader: reader,
            counter: 0,
            buffer: Vec::<u8>::with_capacity(DEFAULT_BLOCK_SIZE),
            eof: false,
        });
    }

    /// Returns a [`PZipWriter`] with the specified algorithm, key, and compression.
    ///
    /// [`PZipWriter`]: struct.PZipWriter.html
    pub fn writer<'r, T: io::Write, K: PZipKey>(
        writer: &'r mut T,
        algorithm: Algorithm,
        key: &K,
        compression: Compression,
    ) -> Result<PZipWriter<'r, T>, Error> {
        let mut tags = PZipTags::new();
        tags.extend(algorithm.tags());
        tags.extend(key.tags());

        let kdf = key.kdf();
        let key_bytes = kdf.derive(key.material(), algorithm, &tags)?;
        let ring_key = algorithm.wrap_key(&key_bytes)?;

        return Ok(PZipWriter {
            pzip: PZip {
                version: 1,
                flags: 1,
                algorithm: algorithm,
                kdf: kdf,
                compression: compression,
                tags: tags,
                key: ring_key,
            },
            writer: writer,
            counter: 0,
            buffer: Vec::<u8>::with_capacity(DEFAULT_BLOCK_SIZE),
            eof: false,
        });
    }

    /// One-shot decryption.
    pub fn decrypt(ciphertext: &[u8], key_material: &[u8]) -> Result<Vec<u8>, Error> {
        let mut input = io::Cursor::new(ciphertext);
        let r = PZip::reader(&mut input, key_material)?;
        let mut plaintext = Vec::<u8>::new();
        for block in r {
            plaintext.extend(block);
        }
        Ok(plaintext)
    }

    /// Streaming decryption.
    pub fn decrypt_to<R: io::Read, W: io::Write>(
        input: &mut R,
        output: &mut W,
        key_material: &[u8],
    ) -> Result<usize, Error> {
        let r = PZip::reader(input, key_material)?;
        let mut total: usize = 0;
        for block in r {
            total += block.len();
            output.write_all(&block)?;
        }
        Ok(total)
    }

    /// One-shot encryption.
    pub fn encrypt<K: PZipKey>(
        plaintext: &[u8],
        algorithm: Algorithm,
        key: &K,
        compression: Compression,
    ) -> Result<Vec<u8>, Error> {
        let mut ciphertext = Vec::<u8>::new();
        let mut w = PZip::writer(&mut ciphertext, algorithm, key, compression)?;
        w.write(plaintext)?;
        w.finalize()?;
        Ok(ciphertext)
    }

    /// Streaming encryption.
    pub fn encrypt_to<R: io::Read, W: io::Write, K: PZipKey>(
        input: &mut R,
        output: &mut W,
        algorithm: Algorithm,
        key: &K,
        compression: Compression,
    ) -> Result<usize, Error> {
        let mut w = PZip::writer(output, algorithm, key, compression)?;
        let mut chunk = [0u8; DEFAULT_BLOCK_SIZE];
        let mut total: usize = 0;
        loop {
            let amt = input.read(&mut chunk)?;
            if amt < 1 {
                break;
            }
            w.write_block(&chunk[..amt])?;
            total += amt;
        }
        w.finalize()?;
        Ok(total)
    }
}

/// Reader for PZip files.
pub struct PZipReader<'a, T: io::Read> {
    pzip: PZip,
    reader: &'a mut T,
    counter: u32,
    buffer: Vec<u8>,
    pub eof: bool,
}

impl<'a, T: io::Read> PZipReader<'a, T> {
    /// Reads and decrypts the next block of data from the stream.
    ///
    /// If the stream has already read the last block, this will return
    /// [`Error::NoMoreBlocks`]. It may also return [`Error::IoError`] for read errors,
    /// or [`Error::CryptoError`] for errors in decryption.
    ///
    /// [`Error::NoMoreBlocks`]: enum.Error.html#variant.NoMoreBlocks
    /// [`Error::IoError`]: enum.Error.html#variant.IoError
    /// [`Error::CryptoError`]: enum.Error.html#variant.CryptoError
    pub fn read_block(&mut self) -> Result<Vec<u8>, Error> {
        if self.eof {
            return Err(Error::NoMoreBlocks);
        }

        let mut bytes = [0u8; 4];
        self.reader.read_exact(&mut bytes)?;
        let header = u32::from_be_bytes(bytes);
        let size = header & 0x00FFFFFF;
        self.eof = (header & 0x80000000) != 0;

        let mut block = vec![0u8; size as usize];
        self.reader.read_exact(&mut block)?;

        let plaintext =
            self.pzip
                .compression
                .decompress(&self.pzip.algorithm.decrypt(
                    &self.pzip.key,
                    &mut block,
                    &self.pzip.tags,
                    self.counter,
                )?)?;

        self.counter += 1;

        Ok(plaintext)
    }
}

impl<'a, T: io::Read> Iterator for PZipReader<'a, T> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_block().ok()
    }
}

impl<'a, T: io::Read> io::Read for PZipReader<'a, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.buffer.len() < buf.len() {
            match self.read_block() {
                Ok(b) => {
                    self.buffer.extend(b);
                }
                Err(Error::CryptoError(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "error decrypting data",
                    ));
                }
                _ => break,
            }
        }

        let amt = cmp::min(buf.len(), self.buffer.len());
        if buf.len() <= self.buffer.len() {
            let (left, right) = self.buffer.split_at(buf.len());
            buf.copy_from_slice(left);
            self.buffer = right.to_vec();
        } else if !self.buffer.is_empty() {
            for (idx, b) in self.buffer.drain(0..).enumerate() {
                buf[idx] = b;
            }
        }

        Ok(amt)
    }
}

/// Writer for PZip files.
pub struct PZipWriter<'a, T: io::Write> {
    pzip: PZip,
    writer: &'a mut T,
    counter: u32,
    buffer: Vec<u8>,
    eof: bool,
}

impl<'a, T: io::Write> PZipWriter<'a, T> {
    /// Writes the PZip header and tags to the stream.
    fn write_header(&mut self) -> Result<(), Error> {
        let mut header = [
            0xB6,
            0x9E,
            0x01,            // version
            self.pzip.flags, // flags
            self.pzip.algorithm as u8,
            self.pzip.kdf as u8,
            self.pzip.compression as u8,
            self.pzip.tags.len() as u8,
        ];
        self.writer.write_all(&mut header)?;
        for (tag, mut tag_data) in &self.pzip.tags {
            let mut tag_header = [*tag as u8, tag_data.len() as u8];
            self.writer.write_all(&mut tag_header)?;
            self.writer.write_all(&mut tag_data)?;
        }
        Ok(())
    }

    fn _write_block(&mut self, block: &[u8], last: bool) -> Result<usize, Error> {
        if self.counter == 0 {
            self.write_header()?;
        }

        let mut ciphertext = self.pzip.algorithm.encrypt(
            &self.pzip.key,
            &self.pzip.compression.compress(&block)?,
            &self.pzip.tags,
            self.counter,
        )?;

        let mut header = ciphertext.len() as u32;
        if last {
            header |= 0x80000000;
        }
        self.writer.write_all(&header.to_be_bytes())?;
        self.writer.write_all(&mut ciphertext)?;
        self.counter += 1;

        Ok(block.len())
    }

    /// Writes a block to the stream.
    ///
    /// The PZip header and tags are not written until this method is called for the
    /// first time. This method may return [`Error::IoError`] for write errors, or
    /// [`Error::CryptoError`] for encryption errors.
    ///
    /// [`write_header`]: struct.PZipWriter.html#method.write_header
    /// [`Error::IoError`]: enum.Error.html#variant.IoError
    /// [`Error::CryptoError`]: enum.Error.html#variant.CryptoError
    pub fn write_block(&mut self, block: &[u8]) -> Result<usize, Error> {
        self._write_block(block, false)
    }

    /// Ensures the last block is written to the stream, and sets `eof`. Returns
    /// [`Error::NoMoreBlocks`] if already at `eof`.
    ///
    /// [`Error::NoMoreBlocks`]: enum.Error.html#variant.NoMoreBlocks
    pub fn finalize(&mut self) -> Result<(), Error> {
        if self.eof {
            return Err(Error::NoMoreBlocks);
        }
        if !self.buffer.is_empty() {
            let block: Vec<u8> = self.buffer.drain(..).collect();
            self._write_block(&block, true)?;
        }
        self.eof = true;
        Ok(())
    }
}

impl<'a, T: io::Write> io::Write for PZipWriter<'a, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend(buf);
        while self.buffer.len() >= DEFAULT_BLOCK_SIZE {
            let block: Vec<u8> = self.buffer.drain(..DEFAULT_BLOCK_SIZE).collect();
            let _written = match self.write_block(&block) {
                Ok(s) => s,
                Err(Error::IoError(e)) => {
                    return Err(e);
                }
                Err(Error::CryptoError(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "error encrypting data",
                    ));
                }
                _ => {
                    return Err(io::Error::new(io::ErrorKind::Other, "unknown error"));
                }
            };
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let block: Vec<u8> = self.buffer.drain(..).collect();
            self.write_block(&block).ok();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // Test archive from https://github.com/imsweb/pzip
    const TEST_DATA: &str =
        "B69E0101010200030220074D651516E68F0561B55B81376F9E38C60F0CDAEABE1CBEFCAC0C414C\
        4541A2FD0400030D40010C53FBD24BF5D4283816135FCF8000001DBF3EC0ACFC989B11099F4A40E\
        3AD5DA75862F9A2B17A915C79D2E6C4B2000000000000000D";

    #[test]
    fn test_pzip_from() {
        let data = hex::decode(TEST_DATA).unwrap();
        let mut reader = io::BufReader::new(&data[..]);
        let mut f = PZip::reader(&mut reader, b"pzip").expect("failed to read header");
        assert_eq!(f.pzip.version, 1);
        assert_eq!(f.pzip.algorithm, Algorithm::AesGcm256);
        assert_eq!(f.pzip.kdf, KeyDerivation::Pbkdf2Sha256);
        assert_eq!(f.pzip.compression, Compression::None);

        let block = f.read_block().expect("failed to read block");
        assert_eq!(block, b"Hello, world!");
    }

    #[test]
    fn test_block_iter() {
        let data = hex::decode(TEST_DATA).unwrap();
        let mut reader = io::BufReader::new(&data[..]);
        let f = PZip::reader(&mut reader, b"pzip").expect("failed to read header");
        let mut plaintext = Vec::<u8>::with_capacity(13);
        for block in f {
            plaintext.extend(block);
        }
        assert_eq!(plaintext, b"Hello, world!");
    }

    #[test]
    fn test_read() {
        let data = hex::decode(TEST_DATA).unwrap();
        let mut reader = io::BufReader::new(&data[..]);
        let mut f = PZip::reader(&mut reader, b"pzip").expect("failed to read header");
        let mut buf = vec![0u8; 4];
        f.read_exact(&mut buf)
            .expect("failed to read first 4 bytes");
        assert_eq!(buf, b"Hell");
        f.read_exact(&mut buf).expect("failed to read next 3 bytes");
        assert_eq!(buf, b"o, w");
        buf.resize(20, 0);
        let amt = f.read(&mut buf).expect("failed to read last 4 bytes");
        assert_eq!(amt, 5);
        assert_eq!(&buf[..amt], b"orld!");
    }

    #[test]
    fn test_round_trip() {
        let mut buf = Vec::<u8>::new();
        let plaintext = b"hello world";
        let key = Password("pzip");
        let mut w =
            PZip::writer(&mut buf, Algorithm::AesGcm256, &key, Compression::Gzip)
                .expect("failed to write header");
        w.write_block(plaintext).expect("failed to write block");
        w.finalize().expect("failed to finalize");

        let mut s = &buf[..];
        let mut r = PZip::reader(&mut s, b"pzip").expect("failed to read header");

        assert_eq!(r.pzip.version, 1);

        let check = r.read_block().expect("failed to read block");
        assert_eq!(check, plaintext);
    }
}
