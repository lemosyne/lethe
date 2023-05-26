use crate::Key;
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    Io, SeekFrom,
};
use std::marker::PhantomData;

pub struct CryptIo<IO, C, const N: usize> {
    key: Key<N>,
    io: IO,
    pd: PhantomData<C>,
}

impl<IO, C, const N: usize> CryptIo<IO, C, N> {
    pub fn new(io: IO, key: Key<N>) -> Self {
        Self {
            io,
            key,
            pd: PhantomData,
        }
    }
}

impl<IO, C, const N: usize> Io for CryptIo<IO, C, N>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO, C, const N: usize> Read for CryptIo<IO, C, N>
where
    IO: Read,
    C: Crypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IO::Error> {
        let mut encrypted = vec![0; buf.len()];
        let n = self.io.read(&mut encrypted)?;

        let decrypted = C::onetime_decrypt(&self.key, &encrypted)
            .map_err(|_| ())
            .unwrap();
        buf.copy_from_slice(&decrypted[..]);

        Ok(n)
    }
}

impl<IO, C, const N: usize> Write for CryptIo<IO, C, N>
where
    IO: Write,
    C: Crypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let encrypted = C::onetime_encrypt(&self.key, buf).map_err(|_| ()).unwrap();
        Ok(self.io.write(&encrypted)?)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}

impl<IO, C, const N: usize> Seek for CryptIo<IO, C, N>
where
    IO: Seek,
    C: Crypter,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.io.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use crypter::openssl::Aes256Ctr;
    use embedded_io::{
        adapters::FromStd,
        blocking::{Read, Seek, Write},
        SeekFrom,
    };
    use hasher::openssl::SHA3_256_MD_SIZE;
    use rand::{thread_rng, RngCore};
    use tempfile::NamedTempFile;

    const BLOCK_SIZE: usize = 4096;
    const KEY_SIZE: usize = SHA3_256_MD_SIZE;

    // Writes 4 blocks of 'a's, then 4 'b's at offset 3.
    #[test]
    fn it_works() -> Result<()> {
        let mut key = [0; KEY_SIZE];
        thread_rng().fill_bytes(&mut key);

        let mut cryptio = CryptIo::<FromStd<NamedTempFile>, Aes256Ctr, KEY_SIZE>::new(
            FromStd::new(NamedTempFile::new()?),
            key,
        );

        cryptio.write_all(&['a' as u8; 4 * BLOCK_SIZE])?;

        let mut buf = vec![0; 4 * BLOCK_SIZE];
        cryptio.seek(SeekFrom::Start(0))?;
        cryptio.read_exact(&mut buf)?;

        assert_eq!(&buf[..], &['a' as u8; 4 * BLOCK_SIZE]);

        Ok(())
    }
}
