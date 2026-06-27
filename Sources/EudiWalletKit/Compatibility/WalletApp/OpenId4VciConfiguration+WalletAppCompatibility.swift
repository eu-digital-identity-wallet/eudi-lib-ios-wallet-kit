//
//  OpenId4VciConfiguration+WalletAppCompatibility.swift
//  EudiWalletKit
//

import Foundation
import CryptoKit
import JOSESwift
import OpenID4VCI
import MdocDataModel18013
import Security

public protocol WalletAttestationsProviderForWalletAppCompatibility: WalletAttestationsProvider {
	func getKeysAttestation(docType: String) async throws -> String?
}

extension OpenId4VciConfiguration {
	func toOpenId4VCIConfigWithPrivateKey(credentialIssuerId: String, clientAttestationPopSigningAlgValuesSupported: [JWSAlgorithm]?) async throws -> OpenId4VCIConfig {
		let client: Client = if let keyAttestationsConfig, clientAttestationPopSigningAlgValuesSupported != nil {
			try await makeAttestationClientWithPrivateKey(
				config: keyAttestationsConfig,
				credentialIssuerId: credentialIssuerId,
				algorithms: clientAttestationPopSigningAlgValuesSupported
			)
		} else {
			.public(id: clientId)
		}
		let clientAttestationPoPBuilder: ClientAttestationPoPBuilder? = if keyAttestationsConfig != nil {
			DefaultClientAttestationPoPBuilder()
		} else {
			nil
		}
		return OpenId4VCIConfig(client: client, authFlowRedirectionURI: authFlowRedirectionURI, authorizeIssuanceConfig: authorizeIssuanceConfig, requirePAR: parUsage, clientAttestationPoPBuilder: clientAttestationPoPBuilder, issuerMetadataPolicy: issuerMetadataPolicy, requireDpop: requireDpop, supportedCredentialReusePolicies: Self.supportedCredentialReusePolicies)
	}

	private func makeAttestationClientWithPrivateKey(config: KeyAttestationConfiguration, credentialIssuerId: String, algorithms: [JWSAlgorithm]?) async throws -> Client {
		let keyId = compatibilityGeneratePopKeyId(credentialIssuerId: credentialIssuerId)
		guard let popConstructor = try await makePoPConstructor(popUsage: .clientAttestation, privateKeyId: keyId, algorithms: algorithms, keyOptions: config.popKeyOptions) else {
			throw PresentationSession.makeError(str: "Failed to create DPoP constructor for client attestation")
		}

		let attestation: String
		if
			let provider = config.walletAttestationsProvider as? any WalletAttestationsProviderForWalletAppCompatibility,
			case .secKey(let privateKey) = popConstructor.privateKey
		{
			attestation = try await provider.getWalletAttestation(signingKey: popConstructor.privateKey)
		} else {
			attestation = try await config.walletAttestationsProvider.getWalletAttestation(signingKey: popConstructor.privateKey)
		}

		guard let signatureAlgorithm = SignatureAlgorithm(rawValue: popConstructor.algorithm.name) else {
			throw PresentationSession.makeError(str: "Unsupported DPoP algorithm: \(popConstructor.algorithm.name) for client attestation")
		}
		let popJwtSpec = try ClientAttestationPoPJWTSpec(
			signingAlgorithm: signatureAlgorithm,
			duration: config.popKeyDuration ?? 300.0,
			typ: "oauth-client-attestation-pop+jwt",
			signingKey: popConstructor.privateKey
		)
		return .attested(
			attestationJWT: try .init(jws: .init(compactSerialization: attestation)),
			popJwtSpec: popJwtSpec
		)
	}

	private func compatibilityGeneratePopKeyId(credentialIssuerId: String) -> String {
		let data = Data(credentialIssuerId.utf8)
		let hash = SHA256.hash(data: data)
		let hashHex = hash.map { String(format: "%02x", $0) }.joined().prefix(16)
		return "client-attestation-\(hashHex)"
	}
}
