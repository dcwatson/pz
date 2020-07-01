use ring::{aead, error::Unspecified, hkdf, hkdf::KeyType, pbkdf2, rand, rand::SecureRandom};
use std::cmp;
use std::collections::HashMap;
use std::io;
use std::num::NonZeroU32;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    IncorrectMagic([u8; 2]),
    UnknownVersion(u8),
    UnknownAlgorithm(u8),
    UnknownKeyDerivation(u8),
    UnknownCompression(u8),
    UnknownTag(u8),
    InvalidKeySize(u8),
    InvalidNonceSize(usize),
    InvalidIterations(u32),
    InvalidIntegerTagSize(usize),
    NonceExhaustion,
    NoMoreBlocks,
    CryptoError(Unspecified),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<Unspecified> for Error {
    fn from(error: Unspecified) -> Self {
        Error::CryptoError(error)
    }
}

const DEFAULT_BLOCK_SIZE: usize = 262144;
const DEFAULT_ITERATIONS: u32 = 200000;

type PZipTags = HashMap<Tag, Vec<u8>>;

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
    use std::convert::TryInto;
    Ok(match bytes.len() {
        1 => bytes[0] as u64,
        2 => u16::from_be_bytes(bytes[0..2].try_into().unwrap()) as u64,
        4 => u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as u64,
        8 => u64::from_be_bytes(bytes[0..8].try_into().unwrap()) as u64,
        n => return Err(Error::InvalidIntegerTagSize(n)),
    })
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    AesGcm256 = 1,
}

impl Algorithm {
    pub fn from(num: u8) -> Result<Algorithm, Error> {
        Ok(match num {
            1 => Algorithm::AesGcm256,
            _ => return Err(Error::UnknownAlgorithm(num)),
        })
    }

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

    pub fn wrap_key(&self, key_bytes: &[u8]) -> Result<aead::LessSafeKey, Error> {
        match *self {
            Algorithm::AesGcm256 => {
                let raw = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)?;
                Ok(aead::LessSafeKey::new(raw))
            }
        }
    }

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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyDerivation {
    Raw = 0,
    HkdfSha256 = 1,
    Pbkdf2Sha256 = 2,
}

impl KeyDerivation {
    pub fn from(num: u8) -> Result<KeyDerivation, Error> {
        Ok(match num {
            0 => KeyDerivation::Raw,
            1 => KeyDerivation::HkdfSha256,
            2 => KeyDerivation::Pbkdf2Sha256,
            _ => return Err(Error::UnknownKeyDerivation(num)),
        })
    }

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
                let iter_bytes = DEFAULT_ITERATIONS.to_be_bytes().to_vec();
                tags.entry(Tag::Iterations).or_insert(iter_bytes);
                tags.entry(Tag::Salt).or_insert(salt);
                tags
            }
        }
    }

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
                let iter_bytes = tags.get(&Tag::Iterations).expect("missing iterations");
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Compression {
    None = 0,
    Gzip = 1,
}

impl Compression {
    pub fn from(num: u8) -> Result<Compression, Error> {
        Ok(match num {
            0 => Compression::None,
            1 => Compression::Gzip,
            _ => return Err(Error::UnknownCompression(num)),
        })
    }
}

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
    pub fn from<'r, T: io::Read>(
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
            let tag = Tag::from(tag_header[0])?; // Should probably just ignore/log this?
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

    pub fn new<'r, T: io::Write>(
        writer: &'r mut T,
        kdf: KeyDerivation,
        key_material: &[u8],
    ) -> Result<PZipWriter<'r, T>, Error> {
        let alg = Algorithm::AesGcm256;
        let mut tags = PZipTags::new();
        tags.extend(alg.tags());
        tags.extend(kdf.tags());

        let key_bytes = kdf.derive(&key_material, alg, &tags)?;
        let key = alg.wrap_key(&key_bytes)?;

        return Ok(PZipWriter {
            pzip: PZip {
                version: 1,
                flags: 1,
                algorithm: alg,
                kdf: kdf,
                compression: Compression::None,
                tags: tags,
                key: key,
            },
            writer: writer,
            counter: 0,
            buffer: Vec::<u8>::with_capacity(DEFAULT_BLOCK_SIZE),
        });
    }

    pub fn decrypt<R: io::Read, W: io::Write>(
        input: &mut R,
        output: &mut W,
        key_material: &[u8],
    ) -> Result<usize, Error> {
        let r = PZip::from(input, key_material)?;
        let mut total: usize = 0;
        for block in r {
            total += block.len();
            output.write_all(&block)?;
        }
        Ok(total)
    }

    pub fn encrypt<R: io::Read, W: io::Write>(
        input: &mut R,
        output: &mut W,
        key_material: &[u8],
    ) -> Result<usize, Error> {
        let mut w = PZip::new(output, KeyDerivation::HkdfSha256, key_material)?;
        let mut chunk = [0u8; DEFAULT_BLOCK_SIZE];
        let mut total: usize = 0;
        loop {
            let amt = input.read(&mut chunk)?;
            if amt < 1 {
                break;
            }
            w.write_block(&chunk[..amt], false)?;
            total += amt;
        }
        Ok(total)
    }
}

pub struct PZipReader<'a, T: io::Read> {
    pzip: PZip,
    reader: &'a mut T,
    counter: u32,
    buffer: Vec<u8>,
    eof: bool,
}

impl<'a, T: io::Read> PZipReader<'a, T> {
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

        let plaintext = self.pzip.algorithm.decrypt(
            &self.pzip.key,
            &mut block,
            &self.pzip.tags,
            self.counter,
        )?;
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

pub struct PZipWriter<'a, T: io::Write> {
    pzip: PZip,
    writer: &'a mut T,
    counter: u32,
    buffer: Vec<u8>,
}

impl<'a, T: io::Write> PZipWriter<'a, T> {
    pub fn write_header(&mut self) -> Result<(), Error> {
        let mut header = [
            0xB6,
            0x9E,
            0x01, // version
            0x00, // flags
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

    pub fn write_block(&mut self, block: &[u8], last: bool) -> Result<usize, Error> {
        if self.counter == 0 {
            self.write_header()?;
        }

        let mut ciphertext =
            self.pzip
                .algorithm
                .encrypt(&self.pzip.key, &block, &self.pzip.tags, self.counter)?;

        let mut header = ciphertext.len() as u32;
        if last {
            header |= 0x80000000;
        }
        self.writer.write_all(&header.to_be_bytes())?;
        self.writer.write_all(&mut ciphertext)?;
        self.counter += 1;

        Ok(block.len())
    }
}

impl<'a, T: io::Write> io::Write for PZipWriter<'a, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend(buf);
        if self.buffer.len() >= DEFAULT_BLOCK_SIZE {
            let block: Vec<u8> = self.buffer.drain(..DEFAULT_BLOCK_SIZE).collect();
            let _written = match self.write_block(&block, false) {
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
            self.write_block(&block, true).ok();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // Test archive from https://github.com/imsweb/pzip
    const TEST_DATA: &str = "B69E0101010200030220074D651516E68F0561B55B81376F9E38C60F0CDAEABE1CBEFCAC0C414C4541A2FD0400030D40010C53FBD24BF5D4283816135FCF8000001DBF3EC0ACFC989B11099F4A40E3AD5DA75862F9A2B17A915C79D2E6C4B2000000000000000D";

    #[test]
    fn test_pzip_from() {
        let data = hex::decode(TEST_DATA).unwrap();
        let mut reader = io::BufReader::new(&data[..]);
        let mut f = PZip::from(&mut reader, b"pzip").expect("failed to read header");
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
        let f = PZip::from(&mut reader, b"pzip").expect("failed to read header");
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
        let mut f = PZip::from(&mut reader, b"pzip").expect("failed to read header");
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
        let mut w = PZip::new(&mut buf, KeyDerivation::Pbkdf2Sha256, b"pzip")
            .expect("failed to write header");
        w.write_block(plaintext, true)
            .expect("failed to write block");

        let mut s = &buf[..];
        let mut r = PZip::from(&mut s, b"pzip").expect("failed to read header");

        assert_eq!(r.pzip.version, 1);

        let check = r.read_block().expect("failed to read block");
        assert_eq!(check, plaintext);
    }

    #[test]
    fn test_one_shot() {
        let plaintext = b"hello world";
        let mut ciphertext = Vec::<u8>::new();
        let mut check = Vec::<u8>::new();
        PZip::encrypt(&mut io::Cursor::new(plaintext), &mut ciphertext, b"pzip")
            .expect("encrypt failed");
        PZip::decrypt(&mut io::Cursor::new(ciphertext), &mut check, b"pzip")
            .expect("decrypt failed");
        assert_eq!(check, plaintext);
    }
}
