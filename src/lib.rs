pub mod error;
pub mod result;

use crypter::Crypter;
use embedded_io::blocking::{Read, Write};
use hasher::Hasher;
use inachus::{blocking::CryptIo, IoGenerator};
use khf::Khf;
use kms::{KeyManagementScheme, Persist};
use rand::{CryptoRng, RngCore};
use std::{collections::HashMap, marker::PhantomData};

const DEFAULT_MASTER_KHF_FANOUTS: &[u64] = &[4, 4, 4, 4];
const DEFAULT_OBJECT_KHF_FANOUTS: &[u64] = &[4, 4, 4, 4];

type ObjId = u64;
type BlkId = u64;
type Key<const N: usize> = [u8; N];

pub struct Lethe<IoG, R, H, C, const N: usize> {
    master_key: Key<N>,
    master_khf: Khf<R, H, N>,
    object_khfs: HashMap<ObjId, Khf<R, H, N>>,
    iog: IoG,
    rng: R,
    pd: PhantomData<C>,
}

impl<IoG, R, H, C, const N: usize> Lethe<IoG, R, H, C, N>
where
    IoG: IoGenerator,
    R: RngCore + CryptoRng + Clone,
    H: Hasher<N>,
{
    pub fn new(iog: IoG, mut rng: R) -> Self {
        Self {
            master_key: Self::random_key(&mut rng),
            master_khf: Khf::new(rng.clone(), DEFAULT_MASTER_KHF_FANOUTS),
            object_khfs: HashMap::new(),
            iog,
            rng,
            pd: PhantomData,
        }
    }

    fn random_key(rng: &mut R) -> Key<N> {
        let mut key = [0; N];
        rng.fill_bytes(&mut key);
        key
    }
}

impl<IoG, R, H, C, const N: usize> KeyManagementScheme for Lethe<IoG, R, H, C, N>
where
    IoG: IoGenerator,
    R: RngCore + CryptoRng + Clone,
    H: Hasher<N>,
{
    type Key = Key<N>;
    type KeyId = (ObjId, BlkId);
    type Error = error::Error;

    fn derive(&mut self, (objid, blkid): Self::KeyId) -> Result<Self::Key, Self::Error> {
        Ok(self.object_khfs.get_mut(&objid).unwrap().derive(blkid)?)
    }

    // TODO: fix object id in KHF.
    fn update(&mut self, (objid, blkid): Self::KeyId) -> Result<Self::Key, Self::Error> {
        self.master_khf.update(objid as u64)?;
        Ok(self.object_khfs.get_mut(&objid).unwrap().update(blkid)?)
    }

    fn commit(&mut self) -> Vec<Self::KeyId> {
        let mut changes = vec![];

        for (objid, khf) in self.object_khfs.iter_mut() {
            changes.extend(khf.commit().into_iter().map(|blkid| (*objid, blkid)));
        }

        self.master_khf.commit();

        changes
    }
}

impl<Io, IoG, R, H, C, const N: usize> Persist<Io> for Lethe<IoG, R, H, C, N>
where
    Io: Read + Write,
    IoG: IoGenerator<Id = u64>,
    <IoG as IoGenerator>::Io: Read + Write,
    R: RngCore + CryptoRng + Clone,
    H: Hasher<N>,
    C: Crypter,
{
    type Init = (Key<N>, IoG, R);

    fn persist(&mut self, sink: Io) -> Result<(), Io::Error> {
        // Persist the object KHFs.
        for (objid, khf) in self.object_khfs.iter_mut() {
            let key = self.master_khf.derive(*objid).unwrap();
            let io = CryptIo::<<IoG as IoGenerator>::Io, C, N>::new(self.iog.generate(*objid), key);
            khf.persist(io).map_err(|_| ()).unwrap();
        }

        // Persist the primary KHF.
        let io = CryptIo::<Io, C, N>::new(sink, self.master_key);
        self.master_khf.persist(io).map_err(|_| ()).unwrap();

        Ok(())
    }

    fn load((master_key, iog, rng): Self::Init, source: Io) -> Result<Self, <Io>::Error> {
        // Load the primary KHF.
        // The object KHFs will be lazy-loaded.
        Ok(Self {
            master_key,
            master_khf: Khf::load(rng.clone(), CryptIo::<Io, C, N>::new(source, master_key))
                .map_err(|_| ())
                .unwrap(),
            object_khfs: HashMap::new(),
            iog,
            rng,
            pd: PhantomData,
        })
    }
}
