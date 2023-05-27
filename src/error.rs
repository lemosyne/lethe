use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error")]
    Io,

    #[error("missing khf")]
    MissingKhf,

    #[error(transparent)]
    Serde(#[from] bincode::Error),

    #[error("no more object ids")]
    ObjIdAllocation,

    #[error(transparent)]
    Khf(#[from] khf::Error),

    #[error("unknown error")]
    Unknown,
}
