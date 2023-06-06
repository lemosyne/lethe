use crate::Key;
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    Io, SeekFrom,
};
use kms::KeyManagementScheme;
use std::marker::PhantomData;

pub struct BlockRecryptIo<'a, IO, CKMS, NKMS, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    io: IO,
    curr_kms: &'a mut CKMS,
    next_kms: &'a mut NKMS,
    pd: PhantomData<C>,
}

impl<'a, IO, CKMS, NKMS, C, const BLK_SZ: usize, const KEY_SZ: usize>
    BlockRecryptIo<'a, IO, CKMS, NKMS, C, BLK_SZ, KEY_SZ>
{
    pub fn new(io: IO, curr_kms: &'a mut CKMS, next_kms: &'a mut NKMS) -> Self {
        Self {
            io,
            curr_kms,
            next_kms,
            pd: PhantomData,
        }
    }
}

impl<'a, IO, CKMS, NKMS, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
    for BlockRecryptIo<'a, IO, CKMS, NKMS, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<'a, IO, CKMS, NKMS, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
    for BlockRecryptIo<'a, IO, CKMS, NKMS, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Seek,
    CKMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    NKMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    C: Crypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let mut size = buf.len();

        let origin = self.io.stream_position()?;
        let mut offset = origin as usize;

        // The offset may be within a block. This requires the bytes before the offset in the block
        // and the bytes after the offset to be read.
        if offset % BLK_SZ != 0 {
            let block = offset / BLK_SZ;
            let fill = offset % BLK_SZ;
            let rest = size.min(BLK_SZ - fill);

            let mut tmp_buf = vec![0; (fill + rest) as usize];
            let off = block * BLK_SZ;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            let actually_read = nbytes - fill;
            if nbytes == 0 || actually_read == 0 {
                self.io.seek(SeekFrom::Start(origin))?;
                return Ok(0);
            }

            let key = self.curr_kms.derive(block as u64).map_err(|_| ()).unwrap();
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

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin + total as u64))?;
                return Ok(total);
            }

            let key = self.curr_kms.derive(block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            buf[total..total + nbytes].copy_from_slice(&tmp_buf[..nbytes]);

            offset += nbytes;
            size -= nbytes;
            total += nbytes;
        }

        self.io.seek(SeekFrom::Start(origin + total as u64))?;

        Ok(total)
    }
}

impl<'a, IO, CKMS, NKMS, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
    for BlockRecryptIo<'a, IO, CKMS, NKMS, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Write + Seek,
    CKMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    NKMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    C: Crypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let mut size = buf.len();

        let origin = self.io.stream_position()?;
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

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin))?;
                return Ok(0);
            }

            let key = self.curr_kms.derive(block as u64).map_err(|_| ()).unwrap();
            let mut tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            tmp_buf[fill..fill + rest].copy_from_slice(&buf[..rest]);

            let key = self.next_kms.derive(block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_encrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            let amount = nbytes.max(fill + rest);
            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf[..amount])?;
            let actually_written = rest.min(nbytes - fill);
            if nbytes == 0 || actually_written == 0 {
                self.io.seek(SeekFrom::Start(origin))?;
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
            let key = self.next_kms.derive(block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_encrypt(&key, &buf[total..total + BLK_SZ])
                .map_err(|_| ())
                .unwrap();

            let off = block * BLK_SZ;
            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin + total as u64))?;
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
            self.io.seek(SeekFrom::Start(off as u64))?;
            let actually_read = self.io.read(&mut tmp_buf)?;
            let actually_write = size.max(actually_read);

            let key = self.curr_kms.derive(block as u64).map_err(|_| ()).unwrap();
            let mut tmp_buf = C::onetime_decrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            tmp_buf[..size].copy_from_slice(&buf[total..total + size]);

            let key = self.next_kms.derive(block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_encrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf[..actually_write])?;
            total += size.min(nbytes as usize);

            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin + total as u64))?;
                return Ok(total);
            }
        }

        self.io.seek(SeekFrom::Start(origin + total as u64))?;

        Ok(total)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}

impl<'a, IO, CKMS, NKMS, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek
    for BlockRecryptIo<'a, IO, CKMS, NKMS, C, BLK_SZ, KEY_SZ>
where
    IO: Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.io.seek(pos)
    }
}
