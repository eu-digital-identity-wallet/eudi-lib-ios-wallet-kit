import Testing
import Foundation
import OpenID4VCI
import MdocDataModel18013
@testable import EudiWalletKit

struct EncryptionSupportConfigTests {

	private let ecOnly = EncryptionSupportConfig(
		credentialResponseEncryptionPolicy: .required,
		ecConfig: EcConfig(ecKeyCurve: .P256),
		rsaConfig: nil
	)

	private func makeConfig(encryptionSupportConfig: EncryptionSupportConfig? = nil) -> OpenId4VciConfiguration {
		if let encryptionSupportConfig {
			OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example", clientId: "wallet", encryptionSupportConfig: encryptionSupportConfig)
		} else {
			OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example", clientId: "wallet")
		}
	}

	@Test func passesConfiguredEncryptionSupportToOpenId4VCIConfig() async throws {
		let vciConfig = try await makeConfig(encryptionSupportConfig: ecOnly)
			.toOpenId4VCIConfig(credentialIssuerId: "https://issuer.example", clientAttestationPopSigningAlgValuesSupported: nil, context: ThreadSafeAuthContext())

		let encryption = vciConfig.encryptionSupportConfig
		#expect(encryption.rsaConfig == nil)
		#expect(encryption.ecConfig?.ecKeyCurve == .P256)
		guard case .required = encryption.credentialResponseEncryptionPolicy else {
			Issue.record("Expected .required response encryption policy")
			return
		}
	}

	@Test func defaultsToLibraryEncryptionSupport() async throws {
		let vciConfig = try await makeConfig()
			.toOpenId4VCIConfig(credentialIssuerId: "https://issuer.example", clientAttestationPopSigningAlgValuesSupported: nil, context: ThreadSafeAuthContext())

		#expect(vciConfig.encryptionSupportConfig.rsaConfig?.rcaKeySize == EncryptionSupportConfig.default.rsaConfig?.rcaKeySize)
	}

	@Test func responseEncryptionSkipsPrimitivesOutsideTheWalletAllowlist() throws {
		let allowlist = EncryptionSupportConfig(
			credentialResponseEncryptionPolicy: .required,
			ecConfig: EcConfig(ecKeyCurve: .P256, supportedJWEAlgorithms: [JWEAlgorithm(.ECDH_ES)]),
			rsaConfig: nil,
			supportedEncryptionMethods: [JOSEEncryptionMethod(.A256GCM), JOSEEncryptionMethod(.A128GCM)]
		)
		let issuerOffersWeakFirst = CredentialResponseEncryption.required(
			algorithmsSupported: [JWEAlgorithm(.RSA1_5), JWEAlgorithm(.RSA_OAEP_256), JWEAlgorithm(.ECDH_ES_A256KW), JWEAlgorithm(.ECDH_ES)],
			encryptionMethodsSupported: [JOSEEncryptionMethod(.A128CBC_HS256), JOSEEncryptionMethod(.A256GCM)],
			compressionMethodsSupported: nil
		)

		let spec = try #require(Issuer.createResponseEncryptionSpec(issuerOffersWeakFirst, walletConfig: allowlist))

		#expect(spec.algorithm.name == "ECDH-ES")
		#expect(spec.encryptionMethod.name == "A256GCM")
	}

	@Test func responseEncryptionFailsWhenIssuerOffersOnlyDisallowedPrimitives() {
		let issuerOffersOnlyWeak = CredentialResponseEncryption.required(
			algorithmsSupported: [JWEAlgorithm(.RSA1_5)],
			encryptionMethodsSupported: [JOSEEncryptionMethod(.A128CBC_HS256)],
			compressionMethodsSupported: nil
		)

		#expect(Issuer.createResponseEncryptionSpec(issuerOffersOnlyWeak, walletConfig: ecOnly) == nil)
	}

	@Test func copyForUnregisteredIssuerKeepsEncryptionSupport() {
		let fallback = makeConfig(encryptionSupportConfig: ecOnly).copy(credentialIssuerURL: "https://other-issuer.example")

		#expect(fallback.encryptionSupportConfig.rsaConfig == nil)
		#expect(fallback.encryptionSupportConfig.ecConfig?.ecKeyCurve == .P256)
	}
}
