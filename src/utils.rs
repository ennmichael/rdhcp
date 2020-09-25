pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    MessageDecoding(String),
    MessageInterpretation(String),
    OptionDecodingFailed,
    OptionEncodingFailed,
}

pub fn copy_slice(dst: &mut [u8], src: &[u8]) {
    if dst.len() >= src.len() {
        dst[..src.len()].copy_from_slice(src)
    } else {
        dst.copy_from_slice(&src[..dst.len()])
    }
}
