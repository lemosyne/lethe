use crate::{Error, Lethe, PersistentStorage};
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    Io, SeekFrom,
};
use hasher::Hasher;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use std::marker::PhantomData;

pub struct BlockCryptIo<'a, P, R, C, H, const KEY_SZ: usize, const BLK_SZ: usize> {
    lethe: &'a mut Lethe<P, R, C, H, KEY_SZ>,
    objid: u64,
    offset: u64,
    pd: PhantomData<C>,
}

impl<'a, P, R, C, H, const KEY_SZ: usize, const BLK_SZ: usize>
    BlockCryptIo<'a, P, R, C, H, KEY_SZ, BLK_SZ>
{
    pub fn new(lethe: &'a mut Lethe<P, R, C, H, KEY_SZ>, objid: u64) -> Self {
        Self {
            lethe,
            objid,
            offset: 0,
            pd: PhantomData,
        }
    }
}

impl<'a, P, R, C, H, const KEY_SZ: usize, const BLK_SZ: usize> Io
    for BlockCryptIo<'a, P, R, C, H, KEY_SZ, BLK_SZ>
where
    P: PersistentStorage,
    for<'b> <P as PersistentStorage>::Io<'b>: Io,
{
    type Error = <P::Io<'a> as Io>::Error;
}

impl<'a, P, R, C, H, const KEY_SZ: usize, const BLK_SZ: usize> Read
    for BlockCryptIo<'a, P, R, C, H, KEY_SZ, BLK_SZ>
where
    P: PersistentStorage<Id = u64>,
    for<'b> <P as PersistentStorage>::Io<'b>: Read + Write + Seek,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<KEY_SZ>,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut io = self.lethe.open_object(self.objid).unwrap();
        io.seek(SeekFrom::Start(self.offset)).unwrap();

        let mut total = 0;
        let mut size = buf.len();

        let origin = io.stream_position()?;
        let mut offset = origin as usize;

        // The offset may be within a block. This requires the bytes before the offset in the block
        // and the bytes after the offset to be read.
        if offset % BLK_SZ != 0 {
            let block = offset / BLK_SZ;
            let fill = offset % BLK_SZ;
            let rest = size.min(BLK_SZ - fill);

            let mut tmp_buf = vec![0; (fill + rest) as usize];
            let off = block * BLK_SZ;

            io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = io.read(&mut tmp_buf)?;
            let actually_read = nbytes - fill;
            if nbytes == 0 || actually_read == 0 {
                self.offset = origin;
                return Ok(0);
            }

            let key = self
                .lethe
                .derive((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            buf[..actually_read].copy_from_slice(&tmp_buf[fill..fill + actually_read]);

            offset += actually_read;
            total += actually_read;
            size -= actually_read;
        }

        // At this point, the offset we want to read from is block-aligned. If it isn't, then we
        // must have read all the bytes. Otherwise, read in the rest of the bytes block-by-block.
        while size > 0 && offset % BLK_SZ == 0 {
            let block = offset / BLK_SZ;
            let rest = size.min(BLK_SZ);

            let mut tmp_buf = vec![0; rest];
            let off = block * BLK_SZ;

            io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                self.offset = origin + total as u64;
                return Ok(total);
            }

            let key = self
                .lethe
                .derive((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            buf[total..total + nbytes].copy_from_slice(&tmp_buf[..nbytes]);

            offset += nbytes;
            size -= nbytes;
            total += nbytes;
        }

        self.offset = origin + total as u64;

        Ok(total)
    }
}

impl<'a, P, R, C, H, const KEY_SZ: usize, const BLK_SZ: usize> Write
    for BlockCryptIo<'a, P, R, C, H, KEY_SZ, BLK_SZ>
where
    P: PersistentStorage<Id = u64>,
    for<'b> <P as PersistentStorage>::Io<'b>: Read + Write + Seek,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<KEY_SZ>,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut io = self.lethe.open_object(self.objid).unwrap();
        io.seek(SeekFrom::Start(self.offset)).unwrap();

        let mut total = 0;
        let mut size = buf.len();

        let origin = io.stream_position()?;
        let mut offset = origin as usize;

        // The write offset may or may not be block-aligned. If it isn't, then the bytes in the
        // block preceding the offset byte should be read as well. The number of bytes to write
        // starting from the offset should be the minimum of the total bytes left to write and the
        // rest of the bytes in the block.
        if offset % BLK_SZ != 0 {
            let block = offset / BLK_SZ;
            let fill = offset % BLK_SZ;
            let rest = size.min(BLK_SZ - fill);

            let mut tmp_buf = vec![0; BLK_SZ];
            let off = block * BLK_SZ;

            io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                self.offset = origin;
                return Ok(0);
            }

            let key = self
                .lethe
                .derive((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let mut tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            tmp_buf[fill..fill + rest].copy_from_slice(&buf[..rest]);

            self.lethe
                .update((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let key = self
                .lethe
                .derive((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let tmp_buf = C::onetime_encrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            let amount = nbytes.max(fill + rest);
            io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = io.write(&tmp_buf[..amount])?;
            let actually_written = rest.min(nbytes - fill);
            if nbytes == 0 || actually_written == 0 {
                self.offset = origin;
                return Ok(0);
            }

            offset += actually_written;
            size -= actually_written;
            total += actually_written;
        }

        // The offset we want to write to should be block-aligned at this point. If not, then we
        // must have written out all the bytes already. Otherwise, write the rest of the bytes
        // block-by-block.
        while size > 0 && size / BLK_SZ > 0 && offset % BLK_SZ == 0 {
            let block = offset / BLK_SZ;
            self.lethe
                .update((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let key = self
                .lethe
                .derive((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let tmp_buf = C::onetime_encrypt(&key, &buf[total..total + BLK_SZ])
                .map_err(|_| ())
                .unwrap();

            let off = block * BLK_SZ;
            io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = io.write(&tmp_buf)?;
            if nbytes == 0 {
                self.offset = origin + total as u64;
                return Ok(total);
            }

            offset += nbytes;
            size -= nbytes;
            total += nbytes;
        }

        // Write any remaining bytes that don't fill an entire block. We handle this specially
        // since we have to read in the block to decrypt the bytes after the overwritten bytes.
        if size > 0 {
            let block = offset / BLK_SZ;

            // Try to read a whole block.
            let mut tmp_buf = vec![0; BLK_SZ];
            let off = block * BLK_SZ;
            io.seek(SeekFrom::Start(off as u64))?;
            io.read(&mut tmp_buf)?;

            let key = self
                .lethe
                .derive((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let mut tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            tmp_buf[..size].copy_from_slice(&buf[total..total + size]);

            self.lethe
                .update((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let key = self
                .lethe
                .derive((self.objid, block as u64))
                .map_err(|_| ())
                .unwrap();
            let tmp_buf = C::onetime_encrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = io.write(&tmp_buf)?;
            total += size.min(nbytes as usize);

            if nbytes == 0 {
                self.offset = origin + total as u64;
                return Ok(total);
            }
        }

        self.offset = origin + total as u64;

        Ok(total)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<'a, P, R, C, H, const KEY_SZ: usize, const BLK_SZ: usize> Seek
    for BlockCryptIo<'a, P, R, C, H, KEY_SZ, BLK_SZ>
where
    P: PersistentStorage,
    for<'b> <P as PersistentStorage>::Io<'b>: Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        Ok(self.offset)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use anyhow::Result;
//     use crypter::openssl::Aes256Ctr;
//     use embedded_io::{
//         adapters::FromStd,
//         blocking::{Read, Seek, Write},
//         SeekFrom,
//     };
//     use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
//     use khf::Khf;
//     use rand::rngs::ThreadRng;
//     use std::convert::identity;
//     use tempfile::NamedTempFile;

//     const BLOCK_SIZE: usize = 4096;
//     const KEY_SIZE: usize = SHA3_256_MD_SIZE;

//     // Writes 4 blocks of 'a's, then 4 'b's at offset 3.
//     #[test]
//     fn offset_write() -> Result<()> {
//         let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

//         let mut blockio = BlockCryptIo::<
//             FromStd<NamedTempFile>,
//             Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
//             Aes256Ctr,
//             fn(u64) -> u64,
//             BLOCK_SIZE,
//             KEY_SIZE,
//         >::new(identity, FromStd::new(NamedTempFile::new()?), &mut khf);

//         blockio.write_all(&['a' as u8; 4 * BLOCK_SIZE])?;
//         blockio.seek(SeekFrom::Start(3))?;
//         blockio.write_all(&['b' as u8; 4])?;

//         let mut buf = vec![0; 4 * BLOCK_SIZE];
//         blockio.seek(SeekFrom::Start(0))?;
//         blockio.read_exact(&mut buf)?;

//         assert_eq!(&buf[..3], &['a' as u8; 3]);
//         assert_eq!(&buf[3..7], &['b' as u8; 4]);
//         assert_eq!(&buf[7..], &['a' as u8; 4 * BLOCK_SIZE - 7]);

//         Ok(())
//     }

//     // Writes 2 blocks of 'a's and a block of 'b' right in the middle.
//     #[test]
//     fn misaligned_write() -> Result<()> {
//         let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

//         let mut blockio = BlockCryptIo::<
//             FromStd<NamedTempFile>,
//             Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
//             Aes256Ctr,
//             fn(u64) -> u64,
//             BLOCK_SIZE,
//             KEY_SIZE,
//         >::new(identity, FromStd::new(NamedTempFile::new()?), &mut khf);

//         blockio.write_all(&['a' as u8; 2 * BLOCK_SIZE])?;
//         blockio.seek(SeekFrom::Start((BLOCK_SIZE / 2) as u64))?;
//         blockio.write_all(&['b' as u8; BLOCK_SIZE])?;

//         let mut buf = vec![0; 2 * BLOCK_SIZE];
//         blockio.seek(SeekFrom::Start(0))?;
//         blockio.read_exact(&mut buf)?;

//         assert_eq!(&buf[..BLOCK_SIZE / 2], &['a' as u8; BLOCK_SIZE / 2]);
//         assert_eq!(
//             &buf[BLOCK_SIZE / 2..BLOCK_SIZE / 2 + BLOCK_SIZE],
//             &['b' as u8; BLOCK_SIZE]
//         );
//         assert_eq!(
//             &buf[BLOCK_SIZE / 2 + BLOCK_SIZE..],
//             &['a' as u8; BLOCK_SIZE / 2]
//         );

//         Ok(())
//     }

//     #[test]
//     fn short_write() -> Result<()> {
//         let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

//         let mut blockio = BlockCryptIo::<
//             FromStd<NamedTempFile>,
//             Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
//             Aes256Ctr,
//             fn(u64) -> u64,
//             BLOCK_SIZE,
//             KEY_SIZE,
//         >::new(identity, FromStd::new(NamedTempFile::new()?), &mut khf);

//         blockio.write_all(&['a' as u8])?;
//         blockio.write_all(&['b' as u8])?;

//         let mut buf = vec![0; 2];
//         blockio.seek(SeekFrom::Start(0))?;
//         blockio.read_exact(&mut buf)?;

//         assert_eq!(&buf[..], &['a' as u8, 'b' as u8]);

//         Ok(())
//     }
// }
