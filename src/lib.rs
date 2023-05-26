mod alloc;
pub mod error;
pub mod io;
pub mod result;

use alloc::Allocator;
use crypter::Crypter;
use embedded_io::blocking::{Read, Write};
use error::Error;
use hasher::Hasher;
use inachus::{IoGenerator, Persist};
use io::CryptIo;
use khf::Khf;
use kms::{KeyManagementScheme, PersistedKeyManagementScheme};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

pub(crate) type Key<const N: usize> = [u8; N];

#[derive(Serialize, Deserialize)]
pub struct Lethe<R, C, H, const N: usize> {
    #[serde(bound(serialize = "Khf<R, H, N>: Serialize"))]
    #[serde(bound(deserialize = "Khf<R, H, N>: Deserialize<'de>"))]
    master_khf: Khf<R, H, N>,
    #[serde(bound(serialize = "Khf<R, H, N>: Serialize"))]
    #[serde(bound(deserialize = "Khf<R, H, N>: Deserialize<'de>"))]
    object_khfs: HashMap<u64, Khf<R, H, N>>,
    mappings: HashMap<u64, u64>,
    allocator: Allocator,
    pd: PhantomData<C>,
}

impl<R, C, H, const N: usize> Lethe<R, C, H, N>
where
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<N>,
{
    /// Creates a new `Lethe` instance.
    pub fn new(fanouts: &[u64], rng: R) -> Self {
        Self {
            master_khf: Khf::new(fanouts, rng.clone()),
            object_khfs: HashMap::new(),
            mappings: HashMap::new(),
            allocator: Allocator::new(),
            pd: PhantomData,
        }
    }

    /// Loads a persisted object `Khf`.
    fn load_khf<IoG>(&mut self, iog: &mut IoG, objid: u64) -> Result<(), Error>
    where
        IoG: IoGenerator<Id = u64>,
        <IoG as IoGenerator>::Io: Read + Write,
    {
        // If the object `Khf` is already loaded, we're done.
        if let Some(true) = self
            .mappings
            .get(&objid)
            .map(|mapped_objid| self.object_khfs.contains_key(mapped_objid))
        {
            return Ok(());
        }

        // Construct the `Io` to load the object `Khf`.
        let mapped_objid = self.mappings[&objid];
        let key = self.master_khf.derive(mapped_objid)?;
        let io = CryptIo::<<IoG as IoGenerator>::Io, C, N>::new(
            iog.generate(mapped_objid).map_err(|_| Error::Io)?,
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
    pub fn get_khf<IoG>(
        &mut self,
        iog: &mut IoG,
        objid: u64,
    ) -> Result<Option<&Khf<R, H, N>>, Error>
    where
        IoG: IoGenerator<Id = u64>,
        <IoG as IoGenerator>::Io: Read + Write,
    {
        self.load_khf(iog, objid)?;
        Ok(self
            .mappings
            .get(&objid)
            .map(|mapped_objid| self.object_khfs.get(mapped_objid))
            .flatten())
    }

    /// Returns a mutable reference to an object `Khf`.
    pub fn get_khf_mut<IoG>(
        &mut self,
        iog: &mut IoG,
        objid: u64,
    ) -> Result<Option<&mut Khf<R, H, N>>, Error>
    where
        IoG: IoGenerator<Id = u64>,
        <IoG as IoGenerator>::Io: Read + Write,
    {
        self.load_khf(iog, objid)?;
        Ok(self
            .mappings
            .get(&objid)
            .map(|mapped_objid| self.object_khfs.get_mut(mapped_objid))
            .flatten())
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

impl<IoG, R, C, H, const N: usize> PersistedKeyManagementScheme<IoG> for Lethe<R, C, H, N>
where
    IoG: IoGenerator<Id = u64>,
    <IoG as IoGenerator>::Io: Read + Write,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<N>,
{
    type Key = Key<N>;
    type KeyId = (u64, u64);
    type Error = Error;

    fn derive(
        &mut self,
        iog: &mut IoG,
        (objid, blkid): Self::KeyId,
    ) -> Result<Self::Key, Self::Error> {
        Ok(self.get_khf_mut(iog, objid)?.unwrap().derive(blkid)?)
    }

    fn update(
        &mut self,
        iog: &mut IoG,
        (objid, blkid): Self::KeyId,
    ) -> Result<Self::Key, Self::Error> {
        Ok(self.get_khf_mut(iog, objid)?.unwrap().update(blkid)?)
    }

    fn commit(&mut self, _: &mut IoG) -> Vec<Self::KeyId> {
        self.object_khfs
            .iter_mut()
            .flat_map(|(objid, khf)| khf.commit().into_iter().map(|blkid| (*objid, blkid)))
            .collect()
    }
}

impl<Io, R, H, C, const N: usize> Persist<Io> for Lethe<R, H, C, N>
where
    R: Default,
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
