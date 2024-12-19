# X3DH
[![Swift](https://img.shields.io/badge/swift-5-blue.svg)](https://swift.org) [![Platform](https://img.shields.io/badge/platform-iOS%20%7C%20macOS%20%7C%20tvOS%20%7C%20watchOS-lightgray.svg)](https://developer.apple.com/swift/) [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A Swift package implementing a modified version of the [X3DH key agreement protocol](https://signal.org/docs/specifications/x3dh/) by Moxie Marlinspike and Trevor Perrin. 

## Overview

From the spec:
> X3DH ("Extended Triple Diffie-Hellman") establishes a shared secret key between two parties who mutually authenticate each other based on public keys. X3DH provides forward secrecy and cryptographic deniability.

> X3DH is designed for asynchronous settings where one user ("Bob") is offline but has published some information to a server. Another user ("Alice") wants to use that information to send encrypted data to Bob, and also establish a shared secret key for future communication.

## Features

* Secure asynchronous key exchange using a variation of the X3DH protocol
* Utilizes EdDSA for signing, instead of XEdDSA as suggested by the spec, and X25519 for key exchange
* Takes advantage of the birational equivalence of the twisted Edwards and Montgomery curves to efficiently convert points between them as necessary
* Uses SHA-512 for the hash function

## Installation

To integrate X3DH into your Xcode project using Swift Package Manager, follow these steps:

1. Open your target in Xcode.
2. Go to "File" -> "Add Package Dependencies...".
3. In the search bar, enter `https://github.com/gossamr/swift-x3dh.git` and click "Add Package".

Then, import the package in your Swift code:
```
import X3DH
```

## Usage

### Generating Initial Key Pair Set

Bob can generate an initial key bundle to publish to a server using the following methods:
*  `generateIdentityKeyPair()`: Generates an identity key pair for signing.
*  `generateOneTimePrekeyPairs(count:)`: Generates a number of one-time prekey pairs.
*  `generateSignedPrekeyPair(idKeyPair:)`: Generates a signed long-lived prekey pair given the previously generated identity keypair.

Note: This package does not manage keys, their storage, distribution, or use.

### Initiating Key Agreement

Alice can retrieve a prekey bundle from the server and initiate a key agreement using the following method:
* `initiateKeyAgreement(remoteIdentityKey:remotePrekey:prekeySignature:remoteOneTimePrekey:idKeyPair:prekey:info:)`: Initiates a key agreement with the given parameters.

Note that `info:` must be an identical ASCII string known and used by both parties, and is intended to be an application identifier as per the spec.

### Completing Key Agreement

Bob can complete the key agreement, having received Alice's public identity key, Alice's ephemeral key, and the one-time prekey she used, using the following method:
* `sharedSecretFromKeyAgreement(remoteIdentityKey:remoteEphemeralKey:usedOneTimePrekeyPair:identityKeyPair:prekeyPair:info:)`: Produces a shared secret with the given parameters.

For an example of a full protocol agreement, see `test3()` in `X3DHTests.swift`.

## Contributing
Contributions are welcome! If you'd like to add features or fix issues, please create a pull request or submit an issue on GitHub.

## Acknowledgments
This package utilizes a fork of the Ed25519 curve from [SwiftEdDSA](https://github.com/leif-ibsen/SwiftEdDSA) which adds key conversion from the twisted Edwards to Montgomery curve. The structure and functional interfaces in this package are heavily influenced by TICE Software's [X3DH](https://github.com/TICESoftware/X3DH) library.

## Disclaimer

This library is intended for research and educational purposes only. It has not been thoroughly audited or reviewed for security vulnerabilities, so its use in production environments is not recommended. If you plan to implement cryptographic protocols in your applications, please consult with a qualified cryptographer or cryptography expert to ensure that you are using secure and audited implementations.
