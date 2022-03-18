use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("kad: can't bootstrap the node: {0}")]
    KadBootstrapError(String),
    #[error("kad: can't provide the key: {0}")]
    KadStartProvidingError(String),
    #[error("kad: can't provide the record: {0}")]
    KadPutRecordEror(String),
}

pub type Result<T> = std::result::Result<T, Error>;
