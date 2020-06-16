use ring::{aead, error::Unspecified, hkdf, pbkdf2, rand, rand::SecureRandom};
use std::cmp;
use std::io;
use std::num::NonZeroU32;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    IncorrectMagic([u8; 4]),
    UnknownVersion(u8),
    InvalidKeySize(u8),
    InvalidNonceSize(u8),
    InvalidIterations(u32),
    NonceExhaustion,
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

const FLAG_COMPRESSED: u8 = 1 << 0;
const FLAG_PASSWORD: u8 = 1 << 1;

#[allow(dead_code)]
pub struct PZip {
    version: u8,
    flags: u8,
    key_size: u8,
    nonce_size: u8,
    salt: [u8; 16],
    iterations: u32,
    size: u64,
    nonce: [u8; 12],
    key: aead::LessSafeKey,
}

impl PZip {
    pub fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    pub fn is_password_key(&self) -> bool {
        self.flags & FLAG_PASSWORD != 0
    }

    pub fn from<'r, T: io::Read>(
        reader: &'r mut T,
        key_material: &[u8],
    ) -> Result<PZipReader<'r, T>, Error> {
        let mut buf = [0u8; 36];
        reader.read_exact(&mut buf)?;

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        if &magic != b"PZIP" {
            return Err(Error::IncorrectMagic(magic));
        }

        let version = buf[4];
        if version != 1 {
            return Err(Error::UnknownVersion(version));
        }

        let flags = buf[5];
        let key_size = buf[6];
        if ![16u8, 32u8].contains(&key_size) {
            return Err(Error::InvalidKeySize(key_size));
        }

        let algorithm = if key_size == 16 {
            &aead::AES_128_GCM
        } else {
            &aead::AES_256_GCM
        };

        let nonce_size = buf[7];
        if nonce_size != 12 {
            return Err(Error::InvalidNonceSize(nonce_size));
        }

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buf[8..24]);

        let iterations = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);

        let size = u64::from_be_bytes([
            buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
        ]);

        let mut nonce = [0u8; 12];
        reader.read_exact(&mut nonce)?;

        let mut key_bytes = vec![0u8; key_size as usize];
        if flags & FLAG_PASSWORD != 0 {
            if iterations < 1 {
                return Err(Error::InvalidIterations(iterations));
            }
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA256,
                NonZeroU32::new(iterations).unwrap(),
                &salt,
                &key_material,
                &mut key_bytes,
            );
        } else {
            hkdf::Salt::new(hkdf::HKDF_SHA256, &salt)
                .extract(&key_material)
                .expand(&[], algorithm)?
                .fill(&mut key_bytes)?;
        }

        let raw = aead::UnboundKey::new(algorithm, &key_bytes)?;

        return Ok(PZipReader {
            pzip: PZip {
                version: version,
                flags: flags,
                key_size: key_size,
                nonce_size: nonce_size,
                salt: salt,
                iterations: iterations,
                size: size,
                nonce: nonce,
                key: aead::LessSafeKey::new(raw),
            },
            reader: reader,
            counter: 0,
            buffer: Vec::<u8>::with_capacity(DEFAULT_BLOCK_SIZE),
        });
    }

    pub fn new<'r, T: io::Write>(
        writer: &'r mut T,
        key_material: &[u8],
    ) -> Result<PZipWriter<'r, T>, Error> {
        let rng = rand::SystemRandom::new();

        let mut salt = [0u8; 16];
        rng.fill(&mut salt)?;

        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce)?;

        let mut key_bytes = [0u8; 32];
        let algorithm = &aead::AES_256_GCM;
        hkdf::Salt::new(hkdf::HKDF_SHA256, &salt)
            .extract(&key_material)
            .expand(&[], algorithm)?
            .fill(&mut key_bytes)?;
        let raw = aead::UnboundKey::new(algorithm, &key_bytes)?;

        let version: u8 = 1;
        let flags: u8 = 0;
        let key_size: u8 = 32;
        let nonce_size: u8 = 12;
        let size: u64 = 0;
        let iterations: u32 = 0;

        // Magic
        writer.write_all(b"PZIP")?;
        // Version, flags, key_size, nonce_size
        writer.write_all(&[version, flags, key_size, nonce_size])?;
        // KDF salt, iterations
        writer.write_all(&salt)?;
        writer.write_all(&iterations.to_be_bytes())?;
        // File size
        writer.write_all(&size.to_be_bytes())?;
        // Nonce
        writer.write_all(&nonce)?;

        return Ok(PZipWriter {
            pzip: PZip {
                version: version,
                flags: flags,
                key_size: key_size,
                nonce_size: nonce_size,
                salt: salt,
                iterations: iterations,
                size: size,
                nonce: nonce,
                key: aead::LessSafeKey::new(raw),
            },
            writer: writer,
            counter: 0,
            buffer: Vec::<u8>::with_capacity(DEFAULT_BLOCK_SIZE),
        });
    }

    pub fn block_nonce(&self, counter: u32) -> Result<aead::Nonce, Error> {
        if counter == u32::MAX {
            return Err(Error::NonceExhaustion);
        }

        let mut next = self.nonce.clone();
        let ctr = counter.to_be_bytes();
        next[8] ^= ctr[0];
        next[9] ^= ctr[1];
        next[10] ^= ctr[2];
        next[11] ^= ctr[3];

        Ok(aead::Nonce::assume_unique_for_key(next))
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
        let mut w = PZip::new(output, key_material)?;
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
        Ok(total)
    }
}

pub struct PZipReader<'a, T: io::Read> {
    pzip: PZip,
    reader: &'a mut T,
    counter: u32,
    buffer: Vec<u8>,
}

impl<'a, T: io::Read> PZipReader<'a, T> {
    pub fn read_block(&mut self) -> Result<Vec<u8>, Error> {
        let mut header = [0u8; 4];
        self.reader.read_exact(&mut header)?;
        let size = u32::from_be_bytes(header);

        let mut block = vec![0u8; size as usize];
        self.reader.read_exact(&mut block)?;

        let nonce = self.pzip.block_nonce(self.counter)?;
        let plaintext = self
            .pzip
            .key
            .open_in_place(nonce, aead::Aad::empty(), &mut block)?;

        self.counter += 1;

        Ok(plaintext.to_vec())
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
    pub fn write_block(&mut self, block: &[u8]) -> Result<usize, Error> {
        let block_size = (block.len() + 16) as u32;
        self.writer.write_all(&block_size.to_be_bytes())?;

        let mut data = block.to_vec();
        let nonce = self.pzip.block_nonce(self.counter)?;
        self.pzip
            .key
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut data)?;
        self.writer.write_all(&data)?;

        self.counter += 1;

        Ok(block.len())
    }
}

impl<'a, T: io::Write> io::Write for PZipWriter<'a, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend(buf);
        if self.buffer.len() >= DEFAULT_BLOCK_SIZE {
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
    const TEST_DATA: &str = "505A49500102200C086F58741C96B2C27A8DA2716422702A00030D40000000000000000B9266AEA55A27210430B6086F000000152D9C7FF9665B9C444C78DA54E0529422035CC1FD930000001682E078BEFEA66C5BA96A066979E8506D27C3610B2F8E";

    #[test]
    fn test_pzip_from() {
        let data = hex::decode(TEST_DATA).unwrap();
        let mut reader = io::BufReader::new(&data[..]);
        let mut f = PZip::from(&mut reader, b"pzip").expect("failed to read header");
        assert_eq!(f.pzip.version, 1);
        assert_eq!(f.pzip.is_compressed(), false);
        assert_eq!(f.pzip.is_password_key(), true);
        assert_eq!(f.pzip.key_size, 32);
        assert_eq!(f.pzip.nonce_size, 12);
        assert_eq!(f.pzip.salt.len(), 16);
        assert_eq!(f.pzip.iterations, 200000);
        assert_eq!(f.pzip.size, 11);

        let block1 = f.read_block().expect("failed to read block");
        assert_eq!(block1, b"hello");

        let block2 = f.read_block().expect("failed to read block");
        assert_eq!(block2, b" world");
    }

    #[test]
    fn test_block_iter() {
        let data = hex::decode(TEST_DATA).unwrap();
        let mut reader = io::BufReader::new(&data[..]);
        let f = PZip::from(&mut reader, b"pzip").expect("failed to read header");
        let mut plaintext = Vec::<u8>::with_capacity(11);
        for block in f {
            plaintext.extend(block);
        }
        assert_eq!(plaintext, b"hello world");
    }

    #[test]
    fn test_read() {
        let data = hex::decode(TEST_DATA).unwrap();
        let mut reader = io::BufReader::new(&data[..]);
        let mut f = PZip::from(&mut reader, b"pzip").expect("failed to read header");
        let mut buf = vec![0u8; 4];
        f.read_exact(&mut buf)
            .expect("failed to read first 4 bytes");
        assert_eq!(buf, b"hell");
        buf.truncate(3);
        f.read_exact(&mut buf).expect("failed to read next 3 bytes");
        assert_eq!(buf, b"o w");
        buf.resize(20, 0);
        let amt = f.read(&mut buf).expect("failed to read last 4 bytes");
        assert_eq!(amt, 4);
        assert_eq!(&buf[..amt], b"orld");
    }

    #[test]
    fn test_round_trip() {
        let mut buf = Vec::<u8>::new();
        let plaintext = b"hello world";
        let mut w = PZip::new(&mut buf, b"pzip").expect("failed to write header");
        w.write_block(plaintext).expect("failed to write block");

        let mut s = &buf[..];
        let mut r = PZip::from(&mut s, b"pzip").expect("failed to read header");

        assert_eq!(r.pzip.version, 1);
        assert_eq!(r.pzip.is_compressed(), false);
        assert_eq!(r.pzip.is_password_key(), false);
        assert_eq!(r.pzip.key_size, 32);
        assert_eq!(r.pzip.nonce_size, 12);
        assert_eq!(r.pzip.salt.len(), 16);
        assert_eq!(r.pzip.iterations, 0);

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
