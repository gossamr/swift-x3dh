//
//  X3DHError.swift
//  X3DHError
//
//  Created by gossamr on 12/13/24.
//

import Foundation

public enum X3DHError: LocalizedError {
    case keyGenerationFailed
    case invalidPrekeySignature
    case keyConversionFailed

    public var errorDescription: String? {
        switch self {
            case .keyGenerationFailed: return "Generation of key pair failed."
            case .invalidPrekeySignature: return "Verification of prekey signature failed."
            case .keyConversionFailed: return "Key type conversion failed."
        }
    }
}
