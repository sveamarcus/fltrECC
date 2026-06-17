# fltrECC
Swift wrapper for Bitcoin Core secp256k1 (libsecp256k1), bundled as a git
submodule pinned to **v0.7.1**.

## fltrWallet
This package is used for elliptic curve encryption in [fltrWallet](https://apps.apple.com/us/app/fltrwallet/id1620857882) for Apple devices.

## Requirements
- **Swift 6.1+** toolchain; the package builds in the **Swift 6 language mode**
  with complete strict-concurrency checking. All public value types are
  `Sendable`.
- The public-key caches use `Synchronization.Mutex`, which sets the Apple
  deployment floor: **macOS 15, iOS 18, tvOS 18, watchOS 11, visionOS 2**.
- **Linux, Android, and Windows** are supported through the same code paths
  (no platform-specific source beyond what `Synchronization` provides).

| Platform | Status |
| --- | --- |
| macOS, Linux | built & tested in CI |
| iOS | built & simulator-tested in CI |
| tvOS, watchOS, visionOS | build-verified in CI |
| Android | cross-compiled & emulator-tested in CI (best-effort) |
| Windows | build-verified in CI (best-effort) |

## Toolchain
The repository pins its Swift toolchain via `.swift-version`. Install
[swiftly](https://www.swift.org/swiftly/), then:
```sh
git clone --recurse-submodules https://github.com/fltrWallet/fltrECC
cd fltrECC
swiftly install        # reads .swift-version
swift build
swift test
```
> On macOS, Swift Testing is provided by Xcode 16+; the swiftly toolchain reuses
> it from the selected Xcode.

## Using
Swift Package Manager (SPM) is supported. SPM fetches the secp256k1 submodule
automatically — no extra steps for consumers. Add a reference to your
`Package.swift` under
```swift
dependencies: [
    ...
    .package(url: "https://github.com/fltrWallet/fltrECC", .upToNextMajor(from: "1.0.0")),
    ...
],
```

### Breaking changes in this release
- The misspelled product `fltrECCAdapater` is renamed to `fltrECCAdapter`; update
  any `.product(name: "fltrECCAdapater", ...)` references.
- `sign(message:)`, `sign(recoverable:)` and `X.SecretKey.sign(message:)` are now
  **throwing**. They validate that the message (and any explicit nonce) is 32
  bytes and `throw C.Error` instead of aborting the process; call them with `try`.
- The unused public `UncheckedScalar` (an unvalidated secret wrapper) has been
  removed.

## Security
- **Constant-time secret comparison.** Equality and ordering of secret values
  (`Scalar`, key pairs, ECDH secrets) run in time independent of the bytes,
  through a `volatile`, branchless C routine, so the position of a first
  difference is not leaked via timing.
- **Secret zeroization.** Secret material is held in a `Buffer` wiped on `deinit`
  via an opaque C call that the optimizer cannot elide. Mutation of a secret
  buffer is internal-only, preserving value semantics and `Sendable` soundness.
- **Graceful input handling.** Parsing and signing reject malformed/out-of-range
  input (bad scalars, points, signatures, recovery ids, message/nonce lengths) by
  returning `nil` or throwing — never by crashing the process.
- **CSPRNG.** Key generation uses the platform CSPRNG (`SystemRandomNumberGenerator`
  — `arc4random`/`getrandom`/`BCryptGenRandom`) with unbiased rejection sampling;
  signing defaults to hedged (random-aux) nonces.
- Validated against the official **BIP-340** known-answer and adversarial vectors.


## Scalar and Point
The most primitive constructs for doing ECC (elliptic curve cryptography). Scalars can be used to instantiate secret keys while Points create public key.

The major difference here between secret keys and scalars (and public keys and points) are that many unsafe operations can be performed directly on Scalars and Points.

For example
```swift
let first = Scalar.random()
let second = Scalar.random()
let third = first * second + first
```
This requires significant understanding of elliptic curve arithmatic but is none the less essential in creating libraries for generating private keys, such as BIP32.

## Optional results
Addition resulting in infinity is statistically next to impossible in its frequency. Some libraries (rightly) treat such occurence as less likely than hardware error. Meaning they wont even check for their occurence. Since Swift is such a handy language at treating optionals, we have gone for the most conservative interpretation of such operations. Consider the following example: 
```swift
let a = Scalar.random()
let b = Scalar.random()
guard let x = a + b else { throw Infinity() }
```
There is this theoretical chance that the addition results in `x = 0`, which is not within the domain of elliptic curve operations.

## SecretKey and PublicKey
There are two sets of secret and public keys. One set starting with DSA for the old way of encoding, decoding and encrypting. Schnorr signatures and their updated encoding are implemented under the X prefix. Operations for recoverable signatures and diffie hellman secret sharing are only available in the DSA types.

## fltrECCTesting
There is a testing library to simplify writing unit tests or integration tests where ECC types are needed. It provides for numerical types instead of its formal counterparts. Let us have a look at an example explaining its use:
```swift
import fltrECC
import fltrECCTesting

let scalar: Scalar = 12
let publicKey = X.PublicKey(15)
```
This would be highly dangerous in proper code but very useful in unit tests where the added expressivity makes for easier to read tests.

## fltrECCAdapter
This is the lowest level module that can be imported if you only want assistance in wrapping the `libsecp256k1` library. It lives under the `C` namespaces such as `C.negate(into: scalar)`. 

## Attribution
This project **fltrBtc** includes **libsecp256k1** of **Bitcoin Core**, under the following license:
```
Copyright (c) 2013 Pieter Wuille

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
