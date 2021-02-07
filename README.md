# Rustica Keys 
Rustica Keys is the library the powers certificate parsing, creation, and signing in the Rustica project. It was originally based on `rust-sshkeys` by @dnaeon (and his licence is present at the top of `mod.rs` in the ssh module) but has been significantly expanded to offer a greater writer API, certificate signature validation, issuing new certificates, and more.

The library also contains other key functionality for Yubikeys key management as Rustica only uses hardware devices to hold private keys. The Yubikey management module can be used to provision slot with keys that can never leave the device. When configuring Rustica for the first time, it's recommended you do this for user private keys, but the CA keys should be loaded on outside Rustica (for backup purposes).

## Builds
![macOS and Ubuntu Builds](https://github.com/obelisk/rustica-keys/workflows/macOS%20+%20Ubuntu/badge.svg)

## API Stability
The API for this crate should not be considered stable and expect breaking changes between versions.


## Security Warning
No review has been done. I built it because I thought people could find it useful. Be wary about using this in production without doing a thorough code review.


## Licence
This software is provided under the MIT licence so you may use it basically however you wish so long as all distributions and derivatives (source and binary) include the copyright from the `LICENSE`.