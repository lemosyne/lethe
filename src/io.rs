use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Write},
    Io,
};
use std::marker::PhantomData;

type Key<const N: usize> = [u8; N];

pub struct KhfIO<IO, C, const N: usize> {
    key: Key<N>,
    io: IO,
    pd: PhantomData<C>,
}

impl<IO, C, const N: usize> KhfIO<IO, C, N> {
    pub fn new(key: Key<N>, io: IO) -> Self {
        Self {
            key,
            io,
            pd: PhantomData,
        }
    }
}

impl<IO, C, const N: usize> Io for KhfIO<IO, C, N>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO, C, const N: usize> Read for KhfIO<IO, C, N>
where
    IO: Read,
    C: Crypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IO::Error> {
        let mut encrypted = vec![0; buf.len()];
        let n = self.io.read(&mut encrypted)?;

        let decrypted = C::onetime_decrypt(&self.key, &encrypted).unwrap();
        buf.copy_from_slice(&decrypted[..]);

        Ok(n)
    }
}

impl<IO, C, const N: usize> Write for KhfIO<IO, C, N>
where
    IO: Write,
    C: Crypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let encrypted = C::onetime_encrypt(&self.key, buf).unwrap();
        Ok(self.io.write(&encrypted)?)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}
