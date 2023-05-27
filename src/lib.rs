mod alloc;
mod datastore;
pub mod error;
pub mod io;
pub mod result;

use alloc::Allocator;
use crypter::Crypter;
use datastore::{Mode, PersistentStorage};
use embedded_io::blocking::{Read, Seek, Write};
use error::Error;
use hasher::Hasher;
use inachus::Persist;
use io::{BlockCryptIo, CryptIo};
use khf::Khf;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

pub(crate) type Key<const N: usize> = [u8; N];

#[derive(Serialize, Deserialize)]
pub struct Lethe<P, R, C, H, const N: usize> {
    #[serde(bound(serialize = "Khf<R, H, N>: Serialize"))]
    #[serde(bound(deserialize = "Khf<R, H, N>: Deserialize<'de>"))]
    master_khf: Khf<R, H, N>,
    #[serde(bound(serialize = "Khf<R, H, N>: Serialize"))]
    #[serde(bound(deserialize = "Khf<R, H, N>: Deserialize<'de>"))]
    object_khfs: HashMap<u64, Khf<R, H, N>>,
    mappings: HashMap<u64, u64>,
    allocator: Allocator,
    storage: P,
    pd: PhantomData<C>,
}

impl<P, R, C, H, const N: usize> Lethe<P, R, C, H, N>
where
    P: PersistentStorage<Id = u64>,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<N>,
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

    /// Opens an `Io` to an object in the specified mode.
    fn open_object(&mut self, objid: u64, mode: Mode) -> Result<P::Io<'_>, Error> {
        self.mappings
            .get(&objid)
            .map(|mapped_objid| {
                self.storage
                    .open(*mapped_objid, mode)
                    .map_err(|_| Error::Io)
            })
            .ok_or(Error::MissingKhf)?
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
        let io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, N>::new(
            self.open_object(objid, Mode::Read)?,
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
        khf: Khf<R, H, N>,
    ) -> Result<Option<Khf<R, H, N>>, Error> {
        if let Some(mapped_objid) = self.mappings.get(&objid) {
            Ok(self.object_khfs.insert(*mapped_objid, khf))
        } else {
            let mapped_objid = self.allocator.alloc()?;
            self.mappings.insert(objid, mapped_objid);
            Ok(self.object_khfs.insert(mapped_objid, khf))
        }
    }

    /// Returns an immutable reference to an object `Khf`.
    pub fn get_khf(&mut self, objid: u64) -> Result<Option<&Khf<R, H, N>>, Error> {
        self.load_khf(objid)?;
        Ok(self
            .object_khfs
            .get(self.mappings.get(&objid).ok_or(Error::MissingKhf)?))
    }

    /// Returns a mutable reference to an object `Khf`.
    pub fn get_khf_mut(&mut self, objid: u64) -> Result<Option<&mut Khf<R, H, N>>, Error> {
        self.load_khf(objid)?;
        Ok(self
            .object_khfs
            .get_mut(self.mappings.get(&objid).ok_or(Error::MissingKhf)?))
    }

    /// Remove an object `Khf`.
    pub fn remove_khf(&mut self, objid: u64) -> Option<Khf<R, H, N>> {
        self.allocator.dealloc(objid);
        self.mappings
            .remove(&objid)
            .map(|mapped_objid| self.object_khfs.remove(&mapped_objid))
            .flatten()
    }
}

impl<P, R, C, H, const N: usize> KeyManagementScheme for Lethe<P, R, C, H, N>
where
    P: PersistentStorage<Id = u64>,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<N>,
{
    type Key = Key<N>;
    type KeyId = (u64, u64);
    type Error = Error;

    fn derive(&mut self, (objid, blkid): Self::KeyId) -> Result<Self::Key, Self::Error> {
        Ok(self.get_khf_mut(objid)?.unwrap().derive(blkid)?)
    }

    fn update(&mut self, (objid, blkid): Self::KeyId) -> Result<Self::Key, Self::Error> {
        Ok(self.get_khf_mut(objid)?.unwrap().update(blkid)?)
    }

    fn commit(&mut self) -> Vec<Self::KeyId> {
        self.object_khfs
            .iter_mut()
            .flat_map(|(objid, khf)| khf.commit().into_iter().map(|blkid| (*objid, blkid)))
            .collect()
    }
}

impl<P, R, C, H, const N: usize> PersistentStorage for Lethe<P, R, C, H, N>
where
    P: PersistentStorage<Id = u64>,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<N>,
{
    type Id = u64;
    type Io<'a> = BlockCryptIo<'a, P::Io<'a>, Khf<R, H, N>, C, 4096, N>
        where
            R: 'a,
            H: 'a,
            P: 'a,
            C: 'a;
    type Error = Error;

    // Couldn't call the `open_object()` or `get_khf_mut()` functions because the compiler would
    // report multiple mutable borrows at a time. Was also too lazy to look into how to properly
    // implement split borrows for this problem.
    fn open<'a>(&'a mut self, objid: Self::Id, mode: Mode) -> Result<Self::Io<'_>, Self::Error> {
        self.load_khf(objid)?;

        let mapped_objid = self.mappings.get(&objid).ok_or(Error::MissingKhf)?;

        if matches!(mode, Mode::Write) {
            self.master_khf.update(*mapped_objid)?;
        }

        let io = self
            .storage
            .open(*mapped_objid, mode)
            .map_err(|_| Error::Io)?;

        let khf = self
            .object_khfs
            .get_mut(mapped_objid)
            .ok_or(Error::MissingKhf)?;

        Ok(BlockCryptIo::new(io, khf))
    }
}

impl<Io, P, R, H, C, const N: usize> Persist<Io> for Lethe<P, R, H, C, N>
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
