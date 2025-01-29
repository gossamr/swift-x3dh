//
//  X3DHTests.swift
//  X3DHTests
//
//  Created by gossamr on 12/13/24.
//

import XCTest
@testable import X3DH

typealias Bytes = [UInt8]

final class X3DHTests: XCTestCase {
    func test2() throws {
        let a = X3DH()
        let idkp = a.generateIdentityKeyPair()
        let _ = try a.generateSignedPrekeyPair(idKeyPair: idkp)
    }

    func test3() throws {
        // Full flow integration test should produce equivalent secrets
        let bob = X3DH()
        let bobIdentityKeyPair = bob.generateIdentityKeyPair()
        let bobSignedPrekey = try bob.generateSignedPrekeyPair(idKeyPair: bobIdentityKeyPair)
        let bobOneTimePrekey = bob.generateOneTimePrekeyPairs(count: 2)

        let alice = X3DH()
        let aliceIdentityKeyPair = alice.generateIdentityKeyPair()

        // [Alice fetches bob's prekey bundle, containing: bobIdentityKeyPair.pubKey, bobSignedPrekey.signature, bobSignedPrekey.keyPair.pubKey, and bobOneTimePreKey[0].pubKey]
        // Alice rebuilds Bob's Prekey signature object
        let aliceCopyBobSignedPreKeySig = X3DH.Signature(message: bobSignedPrekey.signature.message, sig: bobSignedPrekey.signature.sig, pubKey: bobSignedPrekey.signature.pubKey)

        let keyAgreementInitiation = try alice.initiateKeyAgreement(remoteIdentityKey: bobIdentityKeyPair.pubKey, remotePrekey: bobSignedPrekey.keyPair.pubKey, prekeySignature: aliceCopyBobSignedPreKeySig, remoteOneTimePrekey: bobOneTimePrekey.first!.pubKey, identityKeyPair: aliceIdentityKeyPair, info: "X3DHTest")

        // [Alice sends identity key, ephemeral key and used one-time prekey id to bob]

        let sharedSecret = try bob.sharedSecretFromKeyAgreement(remoteIdentityKey: aliceIdentityKeyPair.pubKey, remoteEphemeralKey: keyAgreementInitiation.ephemeralPublicKey, usedOneTimePrekeyPair: bobOneTimePrekey.first!, identityKeyPair: bobIdentityKeyPair, prekeyPair: bobSignedPrekey.keyPair, info: "X3DHTest")
        XCTAssertTrue(keyAgreementInitiation.sharedSecret == sharedSecret)
    }

    func test4() throws {
        let alice = X3DH()
        let bob = X3DH()
        let aidkp = alice.generateIdentityKeyPair()
        let bidkp = bob.generateIdentityKeyPair()
        let bdhkp = bob.generateOneTimePrekeyPairs(count: 1)
        let dh1 = try aidkp.asDH().privKey.sharedSecretFromKeyAgreement(with: bdhkp.first!.pubKey)
        let dh2 = try bdhkp.first!.privKey.sharedSecretFromKeyAgreement(with: try aidkp.asDH().pubKey)
        let dh3 = try aidkp.asDH().privKey.sharedSecretFromKeyAgreement(with: try bidkp.pubKey.asDH())
        let dh4 = try bidkp.asDH().privKey.sharedSecretFromKeyAgreement(with: try aidkp.pubKey.asDH())
        XCTAssertTrue(dh1 == dh2)
        XCTAssertTrue(dh3 == dh4)
    }

    func test5() throws {
        let alice = X3DH()
        let aidkp = alice.generateIdentityKeyPair()
        let p2p = try aidkp.privKey.asDH().publicKey
        let pc = try aidkp.pubKey.asDH()
        XCTAssertTrue(p2p.rawRepresentation == pc.rawRepresentation)
    }

    func test6() throws {
        let keystring = "3bf918ffc2c955dc895bf145f566fb96623c1cadbe040091175764b5fde322c0"
        let rawkey = keystring.hex as! Bytes
        let idpub = try IDPubKey(r: rawkey)
        let dhkey = idpub.asX25519()
        let got = Data(dhkey).hexEncodedString()
        let want = "efc6c9d0738e9ea18d738ad4a2653631558931b0f1fde4dd58c436d19686dc28"
        XCTAssertTrue(got == want)
    }

    func test7() throws {
        let pk: Bytes = [
            239,  64,  74, 224,  13, 228, 123, 181,
            252,  80, 121, 124, 247,  87, 220, 132,
            177, 188,  62,  53, 244,  83, 192, 101,
            26,  75, 165,  69,  97, 144, 151,  68
        ]
        let idpub = try IDPubKey(r: pk)
        let got = idpub.asX25519()
        let want: Bytes = [
            26,  36, 193, 237, 174, 222, 20,  32,
            241,  80,   5, 182, 209,  94, 20, 249,
            161, 185, 183, 165, 146,  62, 48, 229,
            215, 108,  13,  81, 131, 120, 91, 114
        ]
        XCTAssertTrue(got == want)
    }

    func test8() throws {
        // Converted Ed25519 private key's public key should be equivalent to directly converted Ed25519 public key
        let idsk = IDPrivKey(kind: .ed25519)
        let idpk = IDPubKey(privateKey: idsk)
        let dhsk = try idsk.asDH()
        let dhpk = try idpk.asDH()
        let dhpk2 = dhsk.publicKey
        XCTAssertTrue(dhpk.rawRepresentation == dhpk2.rawRepresentation)
    }
}

fileprivate extension Data {
  /// A hexadecimal string representation of the bytes.
  func hexEncodedString() -> String {
    let hexDigits = Array("0123456789abcdef".utf16)
    var hexChars = [UTF16.CodeUnit]()
    hexChars.reserveCapacity(count * 2)

    for byte in self {
      let (index1, index2) = Int(byte).quotientAndRemainder(dividingBy: 16)
      hexChars.append(hexDigits[index1])
      hexChars.append(hexDigits[index2])
    }

    return String(utf16CodeUnits: hexChars, count: hexChars.count)
  }
}

fileprivate func convertHex(_ s: String.UnicodeScalarView, i: String.UnicodeScalarIndex, appendTo d: [UInt8]) -> [UInt8] {

    let skipChars = CharacterSet.whitespacesAndNewlines

    guard i != s.endIndex else { return d }

    let next1 = s.index(after: i)
    
    if skipChars.contains(s[i]) {
        return convertHex(s, i: next1, appendTo: d)
    } else {
        guard next1 != s.endIndex else { return d }
        let next2 = s.index(after: next1)

        let sub = String(s[i..<next2])
        
        guard let v = UInt8(sub, radix: 16) else { return d }
        
        return convertHex(s, i: next2, appendTo: d + [ v ])
    }
}

fileprivate extension String {
    /// Convert Hexadecimal String to Array<UInt>
    ///     "0123".hex                // [1, 35]
    ///     "aabbccdd 00112233".hex   // 170, 187, 204, 221, 0, 17, 34, 51]
    var hex: some Sequence<UInt8> {
        return convertHex(self.unicodeScalars, i: self.unicodeScalars.startIndex, appendTo: [])
    }

    /// Convert Hexadecimal String to Data
    ///     "0123".hexData                    /// 0123
    ///     "aa bb cc dd 00 11 22 33".hexData /// aabbccdd 00112233
    var hexData : Data {
        return Data(hex)
    }
}

fileprivate extension Substring {
    var hex: some Sequence<UInt8> {
        sequence(state: self, next: { remainder in
            guard remainder.count >= 2 else { return nil }
            let nextTwo = remainder.prefix(2)
            remainder.removeFirst(2)
            return UInt8(nextTwo, radix: 16)
        })
    }
}
