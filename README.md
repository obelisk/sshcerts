# sshcerts
sshcerts (formerly rustica-keys) is a library for parsing, creating, and signing OpenSSH certificates. It was originally based on `rust-sshkeys` by @dnaeon but has been significantly expanded to offer a greater writer API, certificate signature validation, issuing new certificates, parsing encrypted private keys, and more.

This library contains other optional functionality for Yubikey key management. The Yubikey management module can be used to provision slot with keys that can never leave the device and SSH module for SSH signatures backed by a Yubikey. To enable this functionality use the feature `yubikey-support`.

This library attempts to keep as few dependencies as possible so many features are gated behind features. For example, RSA certificates can be read in and verified but not created unless the `rsa-signing` feature is used.

Support for encrypted private keys in available with the `encrypted-keys` features.

Finally there is the x509 module for doing some strange things like getting the SSH public key from an x509 certificate. This is automatically included when using the Yubikey feature but can be enabled separately with `x509-support`

## Builds
![macOS and Ubuntu Builds](https://github.com/obelisk/sshcerts/workflows/macOS%20+%20Ubuntu/badge.svg)

## API Stability
The API for this crate should not be considered stable and expect breaking changes between versions.

## Security Warning
No review has been done. I built it because I thought people could find it useful. Be wary about using this in production without doing a thorough code review.

## Yubikey Benchmarks
Yubikeys are not fast HSMs so running infra generating many certificates per second is going to be a challenge. I have benchmarked several kinds with both 256 and 384 bit ECDSA keys. The results are below:

| | ECDSA256 | ECDSA384 | Notes |
|---|---|---|---|
|4C FIPS <4.4.5>| - | - | Requires pin on sign|
|Nano 4C <4.3.7>| 9.14 | 6.35 ||
|Nano 5C <5.2.4>| 10.58 | 7.10 ||
|5 NFC <5.2.7>| 10.93 | 7.20 ||
|5Ci <5.2.4>| 10.94 | 7.22 ||

This shows 5s are about 15% faster than 4s but between 5s is mostly a wash. Loading the same key on multiple Yubikeys would provide a multiplicative speed up (equal to number of keys) but if you need that many signatures per second, Yubikeys are probably not the way to go.

## Licence
This software is provided under the MIT licence so you may use it basically however you wish so long as all distributions and derivatives (source and binary) include the copyright from the `LICENSE`.