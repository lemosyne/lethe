use crate::Key;
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    Io, SeekFrom,
};
use kms::KeyManagementScheme;
use std::marker::PhantomData;

pub struct BlockCryptIo<IO, KMS, C, const N: usize, const M: usize> {
    io: IO,
    kms: KMS,
    pd: PhantomData<C>,
}

impl<IO, KMS, C, const N: usize, const M: usize> BlockCryptIo<IO, KMS, C, N, M> {
    pub fn new(io: IO, kms: KMS) -> Self {
        Self {
            io,
            kms,
            pd: PhantomData,
        }
    }
}

impl<IO, KMS, C, const N: usize, const M: usize> Io for BlockCryptIo<IO, KMS, C, N, M>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO, KMS, C, const N: usize, const M: usize> Read for BlockCryptIo<IO, KMS, C, N, M>
where
    IO: Io + Read + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = [u8; M]>,
    C: Crypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let mut size = buf.len();
        let mut offset = self.io.stream_position()? as usize;

        // The offset may be within a block. This requires the bytes before the offset in the block
        // and the bytes after the offset to be read.
        if offset % N != 0 {
            let block = offset / N;
            let fill = offset % N;
            let rest = size.min(N - fill);

            let mut tmp_buf = vec![0; (fill + rest) as usize];
            let off = block * N;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            let actually_read = nbytes - fill;
            if nbytes == 0 || actually_read == 0 {
                return Ok(0);
            }

            let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            buf[..actually_read].copy_from_slice(&tmp_buf[fill..fill + actually_read]);

            offset += actually_read;
            total += actually_read;
            size -= actually_read;
        }

        // At this point, the offset we want to read from is block-aligned. If it isn't, then we
        // must have written out all the bytes. Otherwise, read in the rest of the bytes
        // block-by-block.
        while size > 0 && offset % N == 0 {
            let block = offset / N;
            let rest = size.min(N);

            let mut tmp_buf = vec![0; rest];
            let off = block * N;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                return Ok(total);
            }

            let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            buf[total..total + nbytes].copy_from_slice(&tmp_buf[..nbytes]);

            offset += nbytes;
            size -= nbytes;
            total += nbytes;
        }

        Ok(total)
    }
}

impl<IO, KMS, C, const N: usize, const M: usize> Write for BlockCryptIo<IO, KMS, C, N, M>
where
    IO: Io + Read + Write + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<M>>,
    C: Crypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let mut size = buf.len();
        let mut offset = self.io.stream_position()? as usize;

        // The read offset may or may not be block-aligned. If it isn't, then the bytes in the
        // block preceding the offset byte should be read as well. The number of bytes to write
        // starting from the offset should be the minimum of the total bytes left to write and the
        // rest of the bytes in the block.
        if offset % N != 0 {
            let block = offset / N;
            let fill = offset % N;
            let rest = size.min(N - fill);

            let mut tmp_buf = vec![0; N];
            let off = block * N;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                return Ok(0);
            }

            let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
            let mut tmp_buf = C::onetime_encrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            tmp_buf[fill..fill + rest].copy_from_slice(&buf[..rest]);

            self.kms.update(block as u64).map_err(|_| ()).unwrap();
            let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_encrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            let amount = nbytes.max(fill + rest);
            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf[..amount])?;
            let actually_written = rest.min(nbytes - fill);
            if nbytes == 0 || actually_written == 0 {
                return Ok(0);
            }

            offset += actually_written;
            size -= actually_written;
            total += actually_written;
        }

        // The offset we want to write to should be block-aligned at this point. If not, then we
        // must have written out all the bytes already. Otherwise, write the rest of the bytes
        // block-by-block.
        while size > 0 && size / N > 0 && offset % N == 0 {
            let block = offset / N;
            self.kms.update(block as u64).map_err(|_| ()).unwrap();
            let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_encrypt(&key, &buf[total..total + N])
                .map_err(|_| ())
                .unwrap();

            let off = block * N;
            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf)?;
            if nbytes == 0 {
                return Ok(total);
            }

            offset += nbytes;
            size -= nbytes;
            total += nbytes;
        }

        // Write any remaining bytes that don't fill an entire block. We handle this specially
        // since we have to read in the block to decrypt the bytes after the overwritten bytes.
        if size > 0 {
            let block = offset / N;

            let mut tmp_buf = vec![0; size];
            let off = block * N;
            self.io.seek(SeekFrom::Start(off as u64))?;
            self.io.read(&mut tmp_buf)?;

            let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
            let mut tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            tmp_buf[..size].copy_from_slice(&buf[total..total + size]);

            self.kms.update(block as u64).map_err(|_| ()).unwrap();
            let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_encrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf)?;
            total += size.min(nbytes as usize);

            if nbytes == 0 {
                return Ok(total);
            }
        }

        Ok(total)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}

impl<IO, KMS, C, const N: usize, const M: usize> Seek for BlockCryptIo<IO, KMS, C, N, M>
where
    IO: Seek,
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
    use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
    use khf::Khf;
    use rand::rngs::ThreadRng;
    use tempfile::NamedTempFile;

    const BLOCK_SIZE: usize = 4096;
    const KEY_SIZE: usize = SHA3_256_MD_SIZE;

    // Writes 4 blocks of 'a's, then 4 'b's at offset 3.
    #[test]
    fn offset_write() -> Result<()> {
        let mut blockio = BlockCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            Khf::new(ThreadRng::default(), &[4, 4, 4, 4]),
        );

        blockio.write_all(&['a' as u8; 4 * BLOCK_SIZE])?;
        blockio.seek(SeekFrom::Start(3))?;
        blockio.write_all(&['b' as u8; 4])?;

        let mut buf = vec![0; 4 * BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..3], &['a' as u8; 3]);
        assert_eq!(&buf[3..7], &['b' as u8; 4]);
        assert_eq!(&buf[7..], &['a' as u8; 4 * BLOCK_SIZE - 7]);

        Ok(())
    }

    // Writes 2 blocks of 'a's and a block of 'b' right in the middle.
    #[test]
    fn misaligned_write() -> Result<()> {
        let mut blockio = BlockCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            Khf::new(ThreadRng::default(), &[4, 4, 4, 4]),
        );

        blockio.write_all(&['a' as u8; 2 * BLOCK_SIZE])?;
        blockio.seek(SeekFrom::Start(BLOCK_SIZE as u64 / 2))?;
        blockio.write_all(&['b' as u8; BLOCK_SIZE])?;

        let mut buf = vec![0; 2 * BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..BLOCK_SIZE / 2], &['a' as u8; BLOCK_SIZE / 2]);
        assert_eq!(
            &buf[BLOCK_SIZE / 2..BLOCK_SIZE / 2 + BLOCK_SIZE],
            &['b' as u8; BLOCK_SIZE]
        );
        assert_eq!(
            &buf[BLOCK_SIZE / 2 + BLOCK_SIZE..],
            &['a' as u8; BLOCK_SIZE / 2]
        );

        Ok(())
    }

    #[test]
    fn short_write() -> Result<()> {
        let mut blockio = BlockCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            Khf::new(ThreadRng::default(), &[4, 4, 4, 4]),
        );

        blockio.write_all(&['a' as u8])?;
        blockio.write_all(&['b' as u8])?;

        let mut buf = vec![0; 2];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..], &['a' as u8, 'b' as u8]);

        Ok(())
    }
}
