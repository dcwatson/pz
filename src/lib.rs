use ring::{aead, error::Unspecified, pbkdf2};
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
    EncryptionError(Unspecified),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<Unspecified> for Error {
    fn from(error: Unspecified) -> Self {
        Error::EncryptionError(error)
    }
}

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

        let nonce_size = buf[7];
        if nonce_size != 12 {
            return Err(Error::InvalidNonceSize(nonce_size));
        }

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buf[8..24]);

        let iterations = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        if iterations < 1 {
            return Err(Error::InvalidIterations(iterations));
        }

        let size = u64::from_be_bytes([
            buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
        ]);

        let mut nonce = [0u8; 12];
        reader.read_exact(&mut nonce)?;

        let mut key_bytes = vec![0u8; key_size as usize];
        if flags & FLAG_PASSWORD != 0 {
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA256,
                NonZeroU32::new(iterations).unwrap(),
                &salt,
                &key_material,
                &mut key_bytes,
            );
        } else {
        }

        let algorithm = if key_size == 16 {
            &aead::AES_128_GCM
        } else {
            &aead::AES_256_GCM
        };
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
}

pub struct PZipReader<'a, T: io::Read> {
    pzip: PZip,
    reader: &'a mut T,
    counter: u32,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
