import CryptoKit
import Foundation
import MdocDataModel18013
import MdocSecurity18013

/// Keeps attestation keys separate from wallets that register the default software area.
actor KeyAttestationTestSecureArea: SecureArea {
    static let name = "KeyAttestationTest"
    static let supportedEcCurves: [CoseEcCurve] = [.P256]
    // Concurrent tests share this instance and use unique key IDs, so registration
    // never replaces the storage backing a test that is already signing.
    static let shared = KeyAttestationTestSecureArea(storage: InMemorySecureKeyStorage())

    private let base: SoftwareSecureArea

    private init(storage: any SecureKeyStorage) {
        base = .create(storage: storage)
    }

    nonisolated static func create(storage: any SecureKeyStorage) -> KeyAttestationTestSecureArea {
        .init(storage: storage)
    }

    func createKeyBatch(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?) async throws -> [CoseKey] {
        try await base.createKeyBatch(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions)
    }

    func getPublicKey(id: String, index: Int, curve: CoseEcCurve) async throws -> CoseKey {
        try await base.getPublicKey(id: id, index: index, curve: curve)
    }

    func deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) async throws {
        try await base.deleteKeyBatch(id: id, startIndex: startIndex, batchSize: batchSize)
    }

    func deleteKeyInfo(id: String) async throws {
        try await base.deleteKeyInfo(id: id)
    }

    func signature(id: String, index: Int, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?, authenticationContext: ThreadSafeAuthContext) async throws -> Data {
        try await base.signature(id: id, index: index, algorithm: algorithm, dataToSign: dataToSign, unlockData: unlockData, authenticationContext: authenticationContext)
    }

    func keyAgreement(id: String, index: Int, publicKey: CoseKey, unlockData: Data?, authenticationContext: ThreadSafeAuthContext) async throws -> SharedSecret {
        try await base.keyAgreement(id: id, index: index, publicKey: publicKey, unlockData: unlockData, authenticationContext: authenticationContext)
    }

    func getStorage() async -> any SecureKeyStorage {
        await base.getStorage()
    }
}
