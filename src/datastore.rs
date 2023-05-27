use core::fmt::Debug;
use embedded_io::Io;

/// The mode to open an `Io` in.
pub enum Mode {
    Read,
    Write,
}

/// Types that can be used to generate handles to write data to persistent storage.
pub trait PersistentStorage {
    /// The identifier for the target of an `Io`.
    type Id;
    /// The produced `Io` type.
    type Io<'a>: Io
    where
        Self: 'a;
    /// Associated error type.
    type Error: Debug;
    /// Produces a new `Io` that is backed by an arbitrary number of bytes.
    fn open<'a>(&'a mut self, id: Self::Id, mode: Mode) -> Result<Self::Io<'_>, Self::Error>;
}