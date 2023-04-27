pub mod error;
pub mod result;

use crypter::Crypter;
use hasher::Hasher;
use khf::Khf;
use kms::KeyManagementScheme;
use path_macro::path;
use rand::{CryptoRng, RngCore};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

const DEFAULT_MASTER_KHF_FANOUTS: &[u64] = &[4, 4, 4, 4];
const DEFAULT_INODE_KHF_FANOUTS: &[u64] = &[4, 4, 4, 4];

type ObjId = u128;
type BlkId = u64;
type Key<const N: usize> = [u8; N];

pub struct Lethe<C, R, H, const N: usize> {
    root: PathBuf,
    master_khf: Khf<C, R, H, N>,
    object_khfs: HashMap<ObjId, Khf<C, R, H, N>>,
    rng: R,
}

impl<C, R, H, const N: usize> Lethe<C, R, H, N> {
    fn master_key_path<P: AsRef<Path>>(root: P) -> PathBuf {
        path![root / "master.key"]
    }

    fn master_khf_path<P: AsRef<Path>>(root: P) -> PathBuf {
        path![root / "master.khf"]
    }

    fn object_khf_path<P: AsRef<Path>>(root: P, obj: ObjId) -> PathBuf {
        path![root / format!("obj{obj}.khf")]
    }
}

impl<C, R, H, const N: usize> KeyManagementScheme for Lethe<C, R, H, N>
where
    C: Crypter,
    R: RngCore + CryptoRng + Clone,
    H: Hasher<N>,
{
    type Init = (PathBuf, R);
    type Key = Key<N>;
    type KeyId = (ObjId, BlkId);
    type Error = error::Error;
    type PublicParams = ();
    type PrivateParams = ();

    fn setup((root, rng): Self::Init) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self {
            root: root.clone(),
            master_khf: Khf::setup((
                Some(Self::master_key_path(&root)),
                Self::master_khf_path(&root),
                DEFAULT_MASTER_KHF_FANOUTS.to_vec(),
                rng.clone(),
            ))?,
            object_khfs: HashMap::new(),
            rng,
        })
    }

    fn derive(&mut self, (objid, blkid): Self::KeyId) -> Self::Key {
        if !self.object_khfs.contains_key(&objid) {
            self.object_khfs.insert(
                objid,
                Khf::setup((
                    None,
                    Self::object_khf_path(&self.root, objid),
                    DEFAULT_INODE_KHF_FANOUTS.to_vec(),
                    self.rng.clone(),
                ))
                .unwrap(),
            );
        }
        self.object_khfs.get_mut(&objid).unwrap().derive(blkid)
    }

    // TODO: fix object id in KHF.
    fn update(&mut self, (objid, blkid): Self::KeyId) -> Self::Key {
        if !self.object_khfs.contains_key(&objid) {
            self.object_khfs.insert(
                objid,
                Khf::setup((
                    None,
                    Self::object_khf_path(&self.root, objid),
                    DEFAULT_INODE_KHF_FANOUTS.to_vec(),
                    self.rng.clone(),
                ))
                .unwrap(),
            );
        }
        self.master_khf.update(objid as u64);
        self.object_khfs.get_mut(&objid).unwrap().update(blkid)
    }

    fn commit(&mut self) {
        for khf in self.object_khfs.values_mut() {
            khf.commit();
        }
        self.master_khf.commit();
    }

    fn compact(&mut self) {
        for khf in self.object_khfs.values_mut() {
            khf.compact();
        }
        self.master_khf.compact();
    }

    fn persist_public_state(&mut self, _: Self::PublicParams) -> Result<(), Self::Error> {
        for (objid, khf) in self.object_khfs.iter_mut() {
            khf.persist_public_state(Some(self.master_khf.derive(*objid as u64)))?;
        }
        self.master_khf.persist_public_state(None)?;
        Ok(())
    }

    fn persist_private_state(&mut self, _: Self::PrivateParams) -> Result<(), Self::Error> {
        for khf in self.object_khfs.values_mut() {
            khf.persist_private_state(())?;
        }
        self.master_khf.persist_private_state(())?;
        Ok(())
    }

    // TODO: decide when to load in object KHF.
    fn load_public_state(&mut self, _: Self::PublicParams) -> Result<(), Self::Error> {
        self.master_khf.load_public_state(None)?;
        Ok(())
    }

    fn load_private_state(&mut self, _: Self::PrivateParams) -> Result<(), Self::Error> {
        self.master_khf.load_private_state(())?;
        Ok(())
    }
}
