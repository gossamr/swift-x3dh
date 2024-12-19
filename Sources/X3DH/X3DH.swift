//
//  X3DH.swift
//  X3DH
//
//  Created by gossamr on 12/13/24.
//

import CryptoKit
import Foundation
import SwiftEdDSA

public typealias DHPubKey = Curve25519.KeyAgreement.PublicKey
public typealias DHPrivKey = Curve25519.KeyAgreement.PrivateKey
public typealias IDPubKey = PublicKey
public typealias IDPrivKey = PrivateKey

extension IDPubKey {
    func asDH() throws -> DHPubKey {
        return try DHPubKey(rawRepresentation: Data(self.asX25519()))
    }
}

extension IDPrivKey {
    func asDH() throws -> DHPrivKey {
        return try DHPrivKey(rawRepresentation: Data(self.asX25519()))
    }
}

public extension SymmetricKey {
    var data: Data {
        self.withUnsafeBytes { Data($0) }
    }

    var base64string : String {
        self.data.base64EncodedString()
    }
}

fileprivate extension Data {
    var bytes: [UInt8] {
        return self.map { UInt8($0) }
    }
}

public class X3DH {
    // Type wrappers around primitives
    public struct IDKeyPair {
        public let privKey: IDPrivKey
        public let pubKey: IDPubKey
        
        public func asDH() throws -> DHKeyPair {
            let pkey = try privKey.asDH()
            return DHKeyPair(privKey: pkey, pubKey: pkey.publicKey)
        }
    }

    public struct DHKeyPair {
        public let privKey: DHPrivKey
        public let pubKey: DHPubKey
    }

    public struct Signature {
        public let message: Bytes
        public let sig: Bytes
        public let pubKey: IDPubKey

        public func verify() -> Bool {
            return pubKey.verify(signature: self.sig, message: self.message)
        }
    }

    public struct SignedPrekeyPair {
        public let keyPair: DHKeyPair
        public let signature: Signature
    }

    private struct DH {
        let localKeyPair: DHKeyPair
        let remotePubKey: DHPubKey
        
        func sharedSecret() throws -> SharedSecret? {
            return try localKeyPair.privKey.sharedSecretFromKeyAgreement(with: remotePubKey)
        }
    }

    public struct KeyAgreementInitiation {
        public let sharedSecret: SymmetricKey
        public let associatedData: Data
        public let ephemeralPublicKey: DHPubKey
    }

    public init() {}
    
    public func generateIdentityKeyPair() -> IDKeyPair {
        let pkey = IDPrivKey.init(kind: .ed25519)
        return IDKeyPair(privKey: pkey, pubKey: IDPubKey(privateKey: pkey))
    }

    private func generateDHKeyPair() -> DHKeyPair {
        let pkey = DHPrivKey()
        return DHKeyPair(privKey: pkey, pubKey: pkey.publicKey)
    }

    public func generateOneTimePrekeyPairs(count: Int) -> [DHKeyPair] {
        var oneTimePrekeyPairs = [DHKeyPair]()
        for _ in 0..<count {
            oneTimePrekeyPairs.append(generateDHKeyPair())
        }
        return oneTimePrekeyPairs
    }

    public func generateSignedPrekeyPair(idKeyPair: IDKeyPair) throws -> SignedPrekeyPair {
        let dhKeyPair = generateDHKeyPair()
        let sig = try idKeyPair.privKey.sign(message: dhKeyPair.pubKey.rawRepresentation.bytes)
        return SignedPrekeyPair(keyPair: dhKeyPair, signature: Signature(message: dhKeyPair.pubKey.rawRepresentation.bytes, sig: sig, pubKey: idKeyPair.pubKey))
    }

    public func initiateKeyAgreement(remoteIdentityKey: IDPubKey, remotePrekey: DHPubKey, prekeySignature: Signature, remoteOneTimePrekey: DHPubKey?, identityKeyPair: IDKeyPair, prekey: DHPubKey, info: String) throws -> KeyAgreementInitiation {
        guard prekeySignature.verify() else {
            throw X3DHError.invalidPrekeySignature
        }

        let ephemeralKeyPair = generateDHKeyPair()

        let dh1 = DH(localKeyPair: try identityKeyPair.asDH(), remotePubKey: remotePrekey)
        let dh2 = DH(localKeyPair: ephemeralKeyPair, remotePubKey: try  remoteIdentityKey.asDH())
        let dh3 = DH(localKeyPair: ephemeralKeyPair, remotePubKey: remotePrekey)
        let dh4: DH? = remoteOneTimePrekey.map { DH(localKeyPair: ephemeralKeyPair, remotePubKey: $0) }

        let sk = try sharedSecret(DH1: dh1, DH2: dh2, DH3: dh3, DH4: dh4, info: info)

        var ad = Data()
        ad.append(contentsOf: Data(identityKeyPair.pubKey.r))
        ad.append(contentsOf: Data(remoteIdentityKey.r))

        return KeyAgreementInitiation(sharedSecret: sk, associatedData: ad, ephemeralPublicKey: ephemeralKeyPair.pubKey)
    }

    public func sharedSecretFromKeyAgreement(remoteIdentityKey: IDPubKey, remoteEphemeralKey: DHPubKey, usedOneTimePrekeyPair: DHKeyPair?, identityKeyPair: IDKeyPair, prekeyPair: DHKeyPair, info: String) throws -> SymmetricKey {
        let dh1 = DH(localKeyPair: prekeyPair, remotePubKey: try remoteIdentityKey.asDH())
        let dh2 = DH(localKeyPair: try identityKeyPair.asDH(), remotePubKey: remoteEphemeralKey)
        let dh3 = DH(localKeyPair: prekeyPair, remotePubKey: remoteEphemeralKey)
        let dh4: DH? = usedOneTimePrekeyPair.map {
            DH(localKeyPair: $0, remotePubKey: remoteEphemeralKey)
        }

        return try sharedSecret(DH1: dh1, DH2: dh2, DH3: dh3, DH4: dh4, info: info)
    }

    private func sharedSecret(DH1: DH, DH2: DH, DH3: DH, DH4: DH?, info: String) throws -> SymmetricKey {
        guard let dh1 = try DH1.sharedSecret(),
              let dh2 = try DH2.sharedSecret(),
              let dh3 = try DH3.sharedSecret() else {
            throw X3DHError.keyGenerationFailed
        }

        let dh4: SharedSecret? = try {
            guard let dh4 = try DH4?.sharedSecret() else {
                throw X3DHError.keyGenerationFailed
            }
            return dh4
        }()

        var input = Data()
        input.append(contentsOf: Data(repeating: UInt8.max, count: 32))
        dh1.withUnsafeBytes { input.append(contentsOf: $0) }
        dh2.withUnsafeBytes { input.append(contentsOf: $0) }
        dh3.withUnsafeBytes { input.append(contentsOf: $0) }
        if let dh4 = dh4 {
            dh4.withUnsafeBytes { input.append(contentsOf: $0) }
        }

        let salt = Data(repeating: 0, count: 32)
        return HKDF<SHA512>.deriveKey(inputKeyMaterial: SymmetricKey(data: input), salt: salt, info: info.data(using: .utf8)!, outputByteCount: 32)
    }
}

