//
//  OpenId4VciService+WalletAppInternalCompatibility.swift
//  EudiWalletKit
//

import Foundation
import OpenID4VCI
import JOSESwift

extension OpenId4VciService {
	func makeBindingKeyForWalletAppCompatibility(
		publicKeyJWK: ECPublicKey,
		algType: JWSAlgorithm.AlgorithmType,
		signer: SecureAreaSigner,
		funcKeyAttestationJWT: FuncKeyAttestationJWT?
	) throws -> BindingKey {
		_ = funcKeyAttestationJWT
		return .jwt(
			algorithm: JWSAlgorithm(algType),
			jwk: publicKeyJWK,
			privateKey: .custom(signer),
			issuer: config.clientId
		)
	}

	func attachKeyAttestation(to constructor: DPoPConstructor?) async -> DPoPConstructorType? {
		guard let constructor, let provider = config.keyAttestationsConfig?.walletAttestationsProvider else { return constructor }
		do {
			let wte = try await provider.getKeysAttestation(keys: [constructor.jwk], nonce: nil)
			let keyAttestationJWT = try KeyAttestationJWT(jwt: wte)
			return KeyAttestedDPoPConstructor(wrapping: constructor, keyAttestation: keyAttestationJWT)
		} catch {
			logger.info("No key attestation available for the DPoP key, sending an unattested DPoP proof: \(error)")
			return constructor
		}
	}

	func getKeyAttestationJWTForWalletAppCompatibility(_ publicKeys: [ECPublicKey], nonce: String?) async throws -> KeyAttestationJWT {
		guard let additionalOptions = issueReq.keyOptions?.additionalOptions else {
			throw PresentationSession.makeError(str: "additionalOptions not found")
		}
		let provider = self.config.keyAttestationsConfig!.walletAttestationsProvider as? any WalletAttestationsProviderForWalletAppCompatibility
		guard let docType = String(data: additionalOptions, encoding: .utf8),
			  let wte = try await provider?.getKeysAttestation(docType: docType) else {
			throw PresentationSession.makeError(str: "wte not found")
		}
		return try .init(jws: .init(compactSerialization: wte))
	}
}
