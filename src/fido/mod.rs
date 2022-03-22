/// For generating new SSH keys on FIDO devices
pub mod generate;

/// For parsing FIDO related data
pub mod parsing;

/// For signing related code
pub mod signing;

pub use generate::FIDOSSHKey;