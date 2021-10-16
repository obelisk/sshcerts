/// Errors when interacting with the Yubikey FIDO application.
#[derive(Debug)]
pub enum Error {
}

impl std::fmt::Display for Error {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
        }
    }
}
