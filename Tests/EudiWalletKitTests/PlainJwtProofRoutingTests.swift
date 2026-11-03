import Testing
import Foundation
import OpenID4VCI
import JOSESwift
import MdocDataModel18013
@testable import EudiWalletKit

/// Verifies that an EAA issuer which does NOT require key attestation is routed to plain `jwt`
/// proofs, and that the wallet's configured proof policy accepts such a proof.
struct PlainJwtProofRoutingTests {

	/// The policy `OpenId4VciConfiguration.toOpenId4VCIConfig` installs when `allowPlainJwtProof`
	/// is set, mirroring its own algorithm list.
	private var walletPolicy: ProofTypesPolicy {
		.acceptAll(supportedAlgorithms: jwsAlgorithms)
	}

	/// The policy installed when `allowPlainJwtProof` is not set.
	private var haipOnlyPolicy: ProofTypesPolicy {
		.haipCompliant(algorithms: jwsAlgorithms)
	}

	private var jwsAlgorithms: [JWSAlgorithm] {
		[CoseEcCurve.P256, .P384, .P521].compactMap { $0.jwsAlgorithm }
	}

	private func jwtMeta(_ requirement: KeyAttestationRequirement?) -> ProofTypeSupportedMeta {
		ProofTypeSupportedMeta(algorithms: ["ES256"], keyAttestationRequirement: requirement)
	}

	// MARK: - wallet-kit routing decision

	@Test func jwtProofWithoutKeyAttestation_RoutesToPlainJwt() {
		let resolved = resolveProofTypeAttestationSupport(proofTypesSupported: ["jwt": jwtMeta(nil)])
		// Both false is what sends `initSecurityKeys` down the plain-`jwt` branch.
		#expect(resolved.supportsAttestationProofType == false)
		#expect(resolved.supportsJwtProofTypeWithAttestation == false)
		// The plain-jwt branch relies on these algorithms being non-empty.
		#expect(resolved.jwtProofType?.algorithms.isEmpty == false)
	}

	@Test func jwtProofExplicitlyNotRequired_RoutesToPlainJwt() {
		let resolved = resolveProofTypeAttestationSupport(
			proofTypesSupported: ["jwt": jwtMeta(.notRequired), "attestation": jwtMeta(.notRequired)]
		)
		#expect(resolved.supportsAttestationProofType == false)
		#expect(resolved.supportsJwtProofTypeWithAttestation == false)
	}

	@Test func jwtProofRequiringKeyAttestation_DoesNotRouteToPlainJwt() {
		let resolved = resolveProofTypeAttestationSupport(proofTypesSupported: ["jwt": jwtMeta(.requiredNoConstraints)])
		#expect(resolved.supportsJwtProofTypeWithAttestation == true)
	}

	// MARK: - library gate on the chosen binding key

	@Test func policyAcceptsPlainJwtBindingKey_WhenAttestationNotRequired() throws {
		try walletPolicy.validate(
			credentialConfiguration: makeConfiguration(jwtRequirement: nil),
			bindingKey: try makePlainJwtBindingKey()
		)
	}

	@Test func policyRejectsPlainJwtBindingKey_WhenAttestationRequired() throws {
		#expect(throws: (any Error).self) {
			try walletPolicy.validate(
				credentialConfiguration: makeConfiguration(jwtRequirement: .requiredNoConstraints),
				bindingKey: try makePlainJwtBindingKey()
			)
		}
	}

	@Test func haipOnlyPolicyRejectsPlainJwtIssuer_WhenFlagNotSet() throws {
		#expect(throws: (any Error).self) {
			try haipOnlyPolicy.validate(
				credentialConfiguration: makeConfiguration(jwtRequirement: nil),
				bindingKey: try makePlainJwtBindingKey()
			)
		}
	}

	// MARK: - helpers

	private func makePlainJwtBindingKey() throws -> BindingKey {
		let jwk = try ECPublicKey(
			crv: .P256,
			x: "WbbPfH2vTcXhlbl1tTQBK4kYPZ7WOZJZKbGQPjbcTrQ",
			y: "h3RrNKl0WE0NVU7IwxEJr1rXnP2_mP4mfQF1sXnRNPg"
		)
		let attrs: [String: Any] = [
			kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
			kSecAttrKeySizeInBits as String: 256
		]
		guard let secKey = SecKeyCreateRandomKey(attrs as CFDictionary, nil) else {
			struct KeyGenFailed: Error {}
			throw KeyGenFailed()
		}
		return .jwt(algorithm: JWSAlgorithm(.ES256), jwk: jwk, privateKey: .secKey(secKey), issuer: "wallet")
	}

	private func makeConfiguration(jwtRequirement: KeyAttestationRequirement?) -> CredentialSupported {
		let definition = SdJwtVcFormat.CredentialDefinition(type: "VerifiableCredential", claims: [])
		return .sdJwtVc(
			SdJwtVcFormat.CredentialConfiguration(
				scope: nil,
				vct: "test_vct",
				cryptographicBindingMethodsSupported: [],
				credentialSigningAlgValuesSupported: ["ES256"],
				proofTypesSupported: ["jwt": jwtMeta(jwtRequirement)],
				credentialMetadata: nil,
				credentialDefinition: definition
			)
		)
	}
}
