use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error")]
    Io,

    #[error("missing khf")]
    MissingKhf,

    #[error(transparent)]
    Serde(#[from] bincode::Error),

    #[error("couldn't allocate object ID")]
    Alloc,

    #[error("couldn't deallocate object ID")]
    Dealloc,

    #[error(transparent)]
    Khf(#[from] khf::Error),

    #[error("unknown error")]
    Unknown,
}
