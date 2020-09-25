use std::{error, fmt};
use std::fmt::Formatter;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    InvalidMessage,
    MessageDecodingFailed,
    MessageEncodingFailed,
    OptionDecodingFailed,
    OptionEncodingFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            &Self::InvalidMessage => "Some message fields are invalid",
            &Self::MessageDecodingFailed => "Message decoding failed",
            &Self::MessageEncodingFailed => "Message encoding failed",
            &Self::OptionDecodingFailed => "Message option decoding failed",
            &Self::OptionEncodingFailed => "Message option encoding failed",
        };

        write!(f, "{}", msg)
    }
}

impl error::Error for Error {}
