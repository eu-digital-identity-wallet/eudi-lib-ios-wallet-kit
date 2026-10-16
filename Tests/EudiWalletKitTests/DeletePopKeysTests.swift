import Testing
import Foundation
import CryptoKit
import MdocDataModel18013
@testable import EudiWalletKit

/// Verifies that `EudiWallet.deletePopKeys` reaches the POP key batches, which belong to no
/// document and are therefore unreachable from document deletion.
///
/// Serialized: `SecureAreaRegistry` keys by secure-area type name and `OpenId4VCIServiceRegistry`
/// is process-wide, so parallel cases would overwrite each other's registrations.
@Suite(.serialized)
struct DeletePopKeysTests {

	/// Deletes both POP keys for every registered issuer, under the ids `generatePopKeyId` derives.
	@Test func deletesBothPopKeysForTheRegisteredIssuer() async throws {
		let issuerURL = "https://issuer.example/\(UUID().uuidString)"
		let secureArea = RecordingSecureArea(storage: NoopKeyStorage())
		let wallet = try makeWallet(issuerURL: issuerURL, secureArea: secureArea)

		await secureArea.reset()
		await wallet.deletePopKeys(secureAreaName: RecordingSecureArea.name)

		let expected = [PopUsage.dpop, .clientAttestation].map {
			OpenId4VciConfiguration.generatePopKeyId(popUsage: $0, credentialIssuerId: issuerURL)
		}
		// `contains`, not equality: both registries are process-wide singletons, so services
		// registered by other tests legitimately add deletions for their own issuers.
		let deletedBatches = await secureArea.deletedKeyBatchIds
		let deletedInfos = await secureArea.deletedKeyInfoIds
		for keyId in expected {
			#expect(deletedBatches.contains(keyId))
			#expect(deletedInfos.contains(keyId))
		}
	}

	/// The ids are prefixed per usage, so the two POP keys can never collide for one issuer.
	@Test func derivesADistinctIdPerUsage() {
		let issuerURL = "https://issuer.example/\(UUID().uuidString)"
		let dpop = OpenId4VciConfiguration.generatePopKeyId(popUsage: .dpop, credentialIssuerId: issuerURL)
		let attestation = OpenId4VciConfiguration.generatePopKeyId(popUsage: .clientAttestation, credentialIssuerId: issuerURL)

		#expect(dpop != attestation)
		#expect(dpop.hasPrefix("dpop-"))
		#expect(attestation.hasPrefix("client-attestation-"))
	}

	/// An unregistered name makes `SecureAreaRegistry.get(name:)` substitute a different area, so
	/// the guard must stop before deleting anything that belongs to someone else.
	@Test func deletesNothingWhenTheSecureAreaIsNotRegistered() async throws {
		let issuerURL = "https://issuer.example/\(UUID().uuidString)"
		let secureArea = RecordingSecureArea(storage: NoopKeyStorage())
		let wallet = try makeWallet(issuerURL: issuerURL, secureArea: secureArea)

		await secureArea.reset()
		await wallet.deletePopKeys(secureAreaName: "NotRegisteredSecureArea-\(UUID().uuidString)")

		#expect(await secureArea.deletedKeyBatchIds.isEmpty)
		#expect(await secureArea.deletedKeyInfoIds.isEmpty)
	}

	// MARK: - helpers

	/// Registering a VCI configuration is what puts a service in `OpenId4VCIServiceRegistry`
	/// (`EudiWallet.init` → `registerOpenId4VciServices`), which is what `deletePopKeys` iterates.
	private func makeWallet(issuerURL: String, secureArea: any SecureArea) throws -> EudiWallet {
		let config = OpenId4VciConfiguration(
			credentialIssuerURL: issuerURL,
			authFlowRedirectionURI: URL(string: "eudi-openid4ci://authorize")!
		)
		#if canImport(EudiEtsi1196x2)
		let trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef))
		#else
		let trustConfig = TrustConfiguration(rootIaca: [])
		#endif
		let wallet = try EudiWallet(
			eudiWalletConfig: EudiWalletConfiguration(serviceName: "delete-pop-keys-test-\(UUID().uuidString)"),
			trustConfig: trustConfig,
			openID4VciConfigurations: [issuerURL: config],
			secureAreas: [secureArea]
		)
		return wallet
	}
}

/// Records the deletions `deletePopKeys` asks for. Every other requirement is unreachable in
/// these tests and fails loudly rather than returning a misleading value.
private actor RecordingSecureArea: SecureArea {
	static let name = "RecordingSecureArea"
	static let defaultEcCurve: CoseEcCurve = .P256
	static let supportedEcCurves: [CoseEcCurve] = [.P256]

	private let storage: any SecureKeyStorage
	var deletedKeyBatchIds: [String] = []
	var deletedKeyInfoIds: [String] = []

	init(storage: any SecureKeyStorage) { self.storage = storage }

	nonisolated static func create(storage: any SecureKeyStorage) -> RecordingSecureArea {
		RecordingSecureArea(storage: storage)
	}

	func reset() {
		deletedKeyBatchIds = []
		deletedKeyInfoIds = []
	}

	func deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) async throws {
		deletedKeyBatchIds.append(id)
	}

	func deleteKeyInfo(id: String) async throws {
		deletedKeyInfoIds.append(id)
	}

	func getStorage() async -> any SecureKeyStorage { storage }
	nonisolated func defaultSigningAlgorithm(ecCurve: CoseEcCurve) -> SigningAlgorithm { .ES256 }
	func unlockKey(id: String) async throws -> Data? { nil }

	func createKeyBatch(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?) async throws -> [CoseKey] {
		throw Unreachable()
	}
	func getPublicKey(id: String, index: Int, curve: CoseEcCurve) async throws -> CoseKey { throw Unreachable() }
	func getInfoAndCurve(id: String) async throws -> ([String: Data], CoseEcCurve) { throw Unreachable() }
	func getKeyBatchInfo(id: String) async throws -> KeyBatchInfo { throw Unreachable() }
	func signature(id: String, index: Int, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?, authenticationContext: ThreadSafeAuthContext) async throws -> Data {
		throw Unreachable()
	}
	func keyAgreement(id: String, index: Int, publicKey: CoseKey, unlockData: Data?, authenticationContext: ThreadSafeAuthContext) async throws -> SharedSecret {
		throw Unreachable()
	}

	struct Unreachable: Error {}
}

/// `SecureArea.create(storage:)` requires a storage object; nothing in these tests reads it.
private actor NoopKeyStorage: SecureKeyStorage {
	func readKeyInfo(id: String) throws -> [String: Data] { [:] }
	func readKeyData(id: String, index: Int, authenticationContext: ThreadSafeAuthContext) throws -> [String: Data] { [:] }
	func writeKeyInfo(id: String, dict: [String: Data]) throws {}
	func writeKeyDataBatch(id: String, startIndex: Int, dicts: [[String: Data]], keyOptions: KeyOptions?) async throws {}
	func deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) throws {}
	func deleteKeyInfo(id: String) throws {}
}
