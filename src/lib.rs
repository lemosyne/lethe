pub mod error;
pub mod io;
pub mod result;

use hasher::Hasher;
use khf::Khf;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use std::collections::HashMap;

const DEFAULT_MASTER_KHF_FANOUTS: &[u64] = &[4, 4, 4, 4];
const DEFAULT_INODE_KHF_FANOUTS: &[u64] = &[4, 4, 4, 4];

type ObjId = u128;
type BlkId = u64;
type Key<const N: usize> = [u8; N];

pub struct Lethe<R, H, const N: usize> {
    master_key: Key<N>,
    master_khf: Khf<R, H, N>,
    object_khfs: HashMap<ObjId, Khf<R, H, N>>,
    rng: R,
}

impl<R, H, const N: usize> Lethe<R, H, N>
where
    R: RngCore + CryptoRng + Clone,
    H: Hasher<N>,
{
    pub fn new(mut rng: R) -> Self {
        Self {
            master_key: Self::random_key(&mut rng),
            master_khf: Khf::new(rng.clone(), DEFAULT_MASTER_KHF_FANOUTS),
            object_khfs: HashMap::new(),
            rng,
        }
    }

    fn random_key(rng: &mut R) -> Key<N> {
        let mut key = [0; N];
        rng.fill_bytes(&mut key);
        key
    }

    fn load_object_khf(&mut self, objid: ObjId) -> result::Result<()> {
        if self.object_khfs.contains_key(&objid) {
            return Ok(());
        }
        Ok(())
    }
}

impl<R, H, const N: usize> KeyManagementScheme for Lethe<R, H, N>
where
    R: RngCore + CryptoRng + Clone,
    H: Hasher<N>,
{
    type Key = Key<N>;
    type KeyId = (ObjId, BlkId);
    type Error = error::Error;

    fn derive(&mut self, (objid, blkid): Self::KeyId) -> Result<Self::Key, Self::Error> {
        self.load_object_khf(objid)?;
        Ok(self.object_khfs.get_mut(&objid).unwrap().derive(blkid)?)
    }

    // TODO: fix object id in KHF.
    fn update(&mut self, (objid, blkid): Self::KeyId) -> Result<Self::Key, Self::Error> {
        self.master_khf.update(objid as u64)?;
        self.load_object_khf(objid)?;
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

// impl<IO: Read + Write, R, H, const N: usize> Persist<IO> for Lethe<R, H, N> {
//     type Init = R;

//     fn persist(&self, mut sink: IO) -> Result<(), IO::Error> {
//         // TODO: stream serialization
//         let ser = bincode::serialize(&self.state).unwrap();
//         sink.write_all(&ser)
//     }

//     fn load(&self, rng: Self::Init, mut source: IO) -> Result<Self, IO::Error> {
//         let mut raw = vec![];
//         loop {
//             let mut block = [0; 0x4000];
//             let n = source.read(&mut block)?;

//             if n == 0 {
//                 break;
//             }

//             raw.extend(&block[..n]);
//         }

//         // TODO: stream serialization
//         Ok(Khf {
//             state: bincode::deserialize(&raw).unwrap(),
//             rng,
//         })
//     }
// }
