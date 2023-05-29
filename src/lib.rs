mod alloc;
pub mod error;
pub mod io;
pub mod result;

use alloc::Allocator;
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    SeekFrom,
};
use error::Error;
use hasher::Hasher;
use io::{BlockCryptIo, CryptIo};
use khf::Khf;
use kms::KeyManagementScheme;
use persistence::{Persist, PersistentStorage};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

pub(crate) type Key<const N: usize> = [u8; N];

#[derive(Serialize, Deserialize)]
pub struct Lethe<P, R, C, H, const KEY_SZ: usize, const BLK_SZ: usize> {
    #[serde(bound(serialize = "Khf<R, H, KEY_SZ>: Serialize"))]
    #[serde(bound(deserialize = "Khf<R, H, KEY_SZ>: Deserialize<'de>"))]
    master_khf: Khf<R, H, KEY_SZ>,
    #[serde(bound(serialize = "Khf<R, H, KEY_SZ>: Serialize"))]
    #[serde(bound(deserialize = "Khf<R, H, KEY_SZ>: Deserialize<'de>"))]
    object_khfs: HashMap<u64, Khf<R, H, KEY_SZ>>,
    mappings: HashMap<u64, u64>,
    allocator: Allocator,
    pub storage: P,
    pd: PhantomData<C>,
}

impl<P, R, C, H, const KEY_SZ: usize, const BLK_SZ: usize> Lethe<P, R, C, H, KEY_SZ, BLK_SZ>
where
    P: PersistentStorage<Id = u64>,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<KEY_SZ>,
{
    /// Creates a new `Lethe` instance.
    pub fn new(fanouts: &[u64], storage: P) -> Self {
        Self {
            master_khf: Khf::new(fanouts, R::default()),
            object_khfs: HashMap::new(),
            mappings: HashMap::new(),
            allocator: Allocator::new(),
            storage,
            pd: PhantomData,
        }
    }

    /// Loads a persisted object `Khf`.
    fn load_khf(&mut self, objid: u64) -> Result<(), Error> {
        // If the object `Khf` is already loaded, we're done.
        if self
            .object_khfs
            .contains_key(self.mappings.get(&objid).ok_or(Error::MissingKhf)?)
        {
            return Ok(());
        }

        // Construct the `Io` to load the object `Khf`.
        let mapped_objid = self.mappings.get(&objid).ok_or(Error::MissingKhf)?;
        let key = self.master_khf.derive(*mapped_objid)?;
        let io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, KEY_SZ>::new(
            self.storage.read_handle(&objid).map_err(|_| Error::Io)?,
            key,
        );

        // Only IO errors should prevent the object `Khf` from being loaded.
        let khf = Khf::load(io)?;
        self.insert_khf(objid, khf)?;

        Ok(())
    }

    /// Inserts a new `Khf` to track.
    pub fn insert_khf(
        &mut self,
        objid: u64,
        khf: Khf<R, H, KEY_SZ>,
    ) -> Result<Option<Khf<R, H, KEY_SZ>>, Error> {
        if let Some(mapped_objid) = self.mappings.get(&objid) {
            Ok(self.object_khfs.insert(*mapped_objid, khf))
        } else {
            let mapped_objid = self.allocator.alloc()?;
            self.mappings.insert(objid, mapped_objid);
            Ok(self.object_khfs.insert(mapped_objid, khf))
        }
    }

    /// Returns an immutable reference to an object `Khf`.
    pub fn get_khf(&mut self, objid: u64) -> Result<Option<&Khf<R, H, KEY_SZ>>, Error> {
        self.load_khf(objid)?;
        Ok(self
            .object_khfs
            .get(self.mappings.get(&objid).ok_or(Error::MissingKhf)?))
    }

    /// Returns a mutable reference to an object `Khf`.
    pub fn get_khf_mut(&mut self, objid: u64) -> Result<Option<&mut Khf<R, H, KEY_SZ>>, Error> {
        self.load_khf(objid)?;
        Ok(self
            .object_khfs
            .get_mut(self.mappings.get(&objid).ok_or(Error::MissingKhf)?))
    }

    /// Remove an object `Khf`.
    pub fn remove_khf(&mut self, objid: u64) -> Option<Khf<R, H, KEY_SZ>> {
        self.allocator.dealloc(objid);
        self.mappings
            .remove(&objid)
            .map(|mapped_objid| self.object_khfs.remove(&mapped_objid))
            .flatten()
    }
}

impl<P, R, C, H, const KEY_SZ: usize, const BLK_SZ: usize> PersistentStorage
    for Lethe<P, R, C, H, KEY_SZ, BLK_SZ>
where
    P: PersistentStorage<Id = u64>,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<KEY_SZ>,
{
    type Id = u64;
    type Error = Error;
    type Io<'a> = BlockCryptIo<'a, P::Io<'a>, Khf<R, H, KEY_SZ>, C, BLK_SZ, KEY_SZ>
        where
            R: 'a,
            H: 'a,
            P: 'a,
            C: 'a;

    fn create(&mut self, objid: &Self::Id) -> Result<(), Self::Error> {
        self.insert_khf(*objid, Khf::new(&[4, 4, 4, 4], R::default()))?;
        self.storage.create(objid).map_err(|_| Error::Io)
    }

    fn destroy(&mut self, objid: &Self::Id) -> Result<(), Self::Error> {
        self.remove_khf(*objid);
        self.storage.destroy(objid).map_err(|_| Error::Io)
    }

    fn read_handle(&mut self, objid: &Self::Id) -> Result<Self::Io<'_>, Self::Error> {
        self.load_khf(*objid)?;

        let khf = self
            .object_khfs
            .get_mut(self.mappings.get(&objid).ok_or(Error::MissingKhf)?)
            .ok_or(Error::MissingKhf)?;

        let io = self.storage.read_handle(objid).map_err(|_| Error::Io)?;

        Ok(BlockCryptIo::new(io, khf))
    }

    fn write_handle(&mut self, objid: &Self::Id) -> Result<Self::Io<'_>, Self::Error> {
        self.load_khf(*objid)?;

        let mapped_objid = self.mappings.get(&objid).ok_or(Error::MissingKhf)?;

        self.master_khf.update(*mapped_objid)?;

        let khf = self
            .object_khfs
            .get_mut(mapped_objid)
            .ok_or(Error::MissingKhf)?;

        let io = self.storage.rw_handle(objid).map_err(|_| Error::Io)?;

        Ok(BlockCryptIo::new(io, khf))
    }

    fn rw_handle(&mut self, objid: &Self::Id) -> Result<Self::Io<'_>, Self::Error> {
        self.write_handle(objid)
    }

    fn truncate(&mut self, objid: &Self::Id, size: u64) -> Result<(), Self::Error> {
        // Number of bytes past a block.
        let extra = size % BLK_SZ as u64;

        // Need to rewrite the extra bytes.
        if extra > 0 {
            let mut io = self.rw_handle(objid)?;
            let mut buf = vec![0; extra as usize];
            let offset = (size / BLK_SZ as u64) * BLK_SZ as u64;

            // Read in the extra bytes.
            io.seek(SeekFrom::Start(offset)).map_err(|_| Error::Io)?;
            io.read(&mut buf).map_err(|_| Error::Io)?;

            // Write the extra bytes.
            io.seek(SeekFrom::Start(offset)).map_err(|_| Error::Io)?;
            io.write(&buf).map_err(|_| Error::Io)?;
        }

        // Truncate the forest. Not needed for security, but nice for efficiency.
        let keys = (size + (BLK_SZ as u64 - 1)) / BLK_SZ as u64;
        self.get_khf_mut(*objid)?
            .ok_or(Error::MissingKhf)?
            .truncate(keys);

        // Truncate the object itself.
        self.storage.truncate(objid, size).map_err(|_| Error::Io)
    }
}

impl<Io, P, R, H, C, const KEY_SZ: usize, const BLK_SZ: usize> Persist<Io>
    for Lethe<P, R, H, C, KEY_SZ, BLK_SZ>
where
    R: Default,
    for<'a> P: Serialize + Deserialize<'a>,
    Io: Read + Write,
{
    type Error = Error;

    fn persist(&mut self, mut sink: Io) -> Result<(), Self::Error> {
        // TODO: Stream serialization.
        let ser = bincode::serialize(&self)?;
        sink.write_all(&ser).map_err(|_| Error::Io)
    }

    fn load(mut source: Io) -> Result<Self, Self::Error> {
        // TODO: Stream deserialization.
        let mut raw = vec![];
        source.read_to_end(&mut raw).map_err(|_| Error::Io)?;
        Ok(bincode::deserialize(&raw)?)
    }
}
