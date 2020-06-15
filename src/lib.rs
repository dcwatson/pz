use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, Error as AeadError, NewAead};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::io;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    IncorrectMagic(Vec<u8>),
    UnknownVersion(u8),
    InvalidKeySize(u8),
    EncryptionError(AeadError),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<AeadError> for Error {
    fn from(error: AeadError) -> Self {
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
    salt: Vec<u8>,
    iterations: u32,
    size: u64,
    nonce: Vec<u8>,
    key: Vec<u8>,
    counter: u32,
}

impl PZip {
    pub fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    pub fn is_password_key(&self) -> bool {
        self.flags & FLAG_PASSWORD != 0
    }

    pub fn from<T: io::Read>(reader: &mut T, key_material: &[u8]) -> Result<PZip, Error> {
        let mut buf = [0u8; 36];
        reader.read_exact(&mut buf)?;

        let magic = buf[0..4].to_vec();
        if magic != b"PZIP" {
            return Err(Error::IncorrectMagic(magic));
        }

        let version = buf[4];
        if version != 1 {
            return Err(Error::UnknownVersion(version));
        }

        let flags = buf[5];
        let key_size = buf[6];
        if ![16u8, 24u8, 32u8].contains(&key_size) {
            return Err(Error::InvalidKeySize(key_size));
        }

        let nonce_size = buf[7];
        let mut nonce = vec![0u8; nonce_size as usize];
        reader.read_exact(&mut nonce)?;

        let salt = buf[8..24].to_vec();
        let iterations = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);

        let mut key = vec![0u8; key_size as usize];
        if flags & FLAG_PASSWORD != 0 {
            pbkdf2::<Hmac<Sha256>>(&key_material, &salt, iterations, &mut key);
        } else {
            let h = Hkdf::<Sha256>::new(Some(&salt), &key_material);
            h.expand(&[], &mut key).unwrap();
        }

        return Ok(PZip {
            version: version,
            flags: flags,
            key_size: key_size,
            nonce_size: nonce_size,
            salt: salt,
            iterations: iterations,
            size: u64::from_be_bytes([
                buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
            ]),
            nonce: nonce,
            key: key,
            counter: 0,
        });
    }

    fn current_nonce(&self) -> Vec<u8> {
        let mut next = self.nonce.clone();
        let ctr = self.counter.to_be_bytes();
        for i in 0..4 {
            let idx = (self.nonce_size - 4 + i) as usize;
            next[idx] ^= ctr[i as usize];
        }
        return next;
    }

    pub fn read_block<T: io::Read>(&mut self, reader: &mut T) -> Result<Vec<u8>, Error> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        let size = u32::from_be_bytes(header);

        let mut block = vec![0u8; size as usize];
        reader.read_exact(&mut block)?;

        let next = self.current_nonce();
        let aeskey = GenericArray::from_slice(&self.key);
        let nonce = GenericArray::from_slice(&next);
        let cipher = Aes256Gcm::new(aeskey);
        cipher.decrypt_in_place(nonce, &[], &mut block)?;

        self.counter += 1;

        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA: &str = "505A49500102200C086F58741C96B2C27A8DA2716422702A00030D40000000000000000B9266AEA55A27210430B6086F000000152D9C7FF9665B9C444C78DA54E0529422035CC1FD930000001682E078BEFEA66C5BA96A066979E8506D27C3610B2F8E";

    #[test]
    fn test_pzip_from() {
        let data = hex::decode(TEST_DATA).unwrap();
        let mut reader = io::BufReader::new(&data[..]);
        let mut pzip = PZip::from(&mut reader, b"pzip").expect("failed to read header");
        assert_eq!(pzip.version, 1);
        assert_eq!(pzip.is_compressed(), false);
        assert_eq!(pzip.is_password_key(), true);
        assert_eq!(pzip.key_size, 32);
        assert_eq!(pzip.nonce_size, 12);
        assert_eq!(pzip.salt.len(), 16);
        assert_eq!(pzip.iterations, 200000);
        assert_eq!(pzip.size, 11);

        let block1 = pzip.read_block(&mut reader).expect("failed to read block");
        assert_eq!(block1, b"hello");

        let block2 = pzip.read_block(&mut reader).expect("failed to read block");
        assert_eq!(block2, b" world");
    }
}
