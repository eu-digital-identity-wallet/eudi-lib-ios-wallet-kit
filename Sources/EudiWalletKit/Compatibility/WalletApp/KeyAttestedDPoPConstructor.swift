//
//  KeyAttestedDPoPConstructor.swift
//  EudiWalletKit
//

import Foundation
import CryptoKit
import OpenID4VCI
@preconcurrency import JOSESwift

final class KeyAttestedDPoPConstructor: DPoPConstructorType {

	private static let type = "dpop+jwt"
	private static let keyAttestationClaim = "key_attestation"
	private static let method = "POST"

	let algorithm: JWSAlgorithm
	let jwk: JWK
	let privateKey: SigningKeyProxy
	/// The key attestation (`rwscd_rt_wte`) attesting `jwk`, already validated by `KeyAttestationJWT`.
	let keyAttestation: KeyAttestationJWT

	init(algorithm: JWSAlgorithm, jwk: JWK, privateKey: SigningKeyProxy, keyAttestation: KeyAttestationJWT) {
		self.algorithm = algorithm
		self.jwk = jwk
		self.privateKey = privateKey
		self.keyAttestation = keyAttestation
	}

	convenience init(wrapping constructor: DPoPConstructor, keyAttestation: KeyAttestationJWT) {
		self.init(algorithm: constructor.algorithm, jwk: constructor.jwk, privateKey: constructor.privateKey, keyAttestation: keyAttestation)
	}

	func jwt(endpoint: URL, accessToken: String?, nonce: Nonce?) async throws -> String {
		let header = try JWSHeader(parameters: [
			JWTClaimNames.type: Self.type,
			JWTClaimNames.algorithm: algorithm.name,
			JWTClaimNames.JWK: jwk.parameters
		])

		var claims: [String: Any] = [
			JWTClaimNames.issuedAt: Int(Date().timeIntervalSince1970.rounded()),
			JWTClaimNames.htm: Self.method,
			JWTClaimNames.htu: endpoint.absoluteString,
			JWTClaimNames.jwtId: UUID().uuidString,
			Self.keyAttestationClaim: keyAttestation.jws.compactSerializedString
		]
		nonce.map { claims[JWTClaimNames.nonce] = $0.value }
		if let data = accessToken?.data(using: .utf8) {
			claims[JWTClaimNames.ath] = Data(SHA256.hash(data: data)).base64URLEncodedString()
		}

		guard let signatureAlgorithm = SignatureAlgorithm(rawValue: algorithm.name) else {
			throw WalletError(description: "Unsupported DPoP signing algorithm: \(algorithm.name)")
		}
		let payload = Payload(try JSONSerialization.data(withJSONObject: claims))
		let signer = try await Self.makeSigner(header: header, payload: payload, privateKey: privateKey, signatureAlgorithm: signatureAlgorithm)
		return try JWS(header: header, payload: payload, signer: signer).compactSerializedString
	}

	private static func makeSigner(header: JWSHeader, payload: Payload, privateKey: SigningKeyProxy, signatureAlgorithm: SignatureAlgorithm) async throws -> Signer {
		switch privateKey {
		case .secKey(let secKey):
			guard let signer = Signer(signatureAlgorithm: signatureAlgorithm, key: secKey) else {
				throw WalletError(description: "Unable to create a DPoP JWS signer")
			}
			return signer
		case .custom(let asyncSigner):
			// Remote (WSCD) signing: the signature is produced before the JWS is assembled.
			let signature = try await asyncSigner.signAsync((header as DataConvertible).data(), payload.data())
			return Signer(customSigner: PrecomputedDPoPSigner(signature: signature, algorithm: signatureAlgorithm))
		}
	}
}

/// Hands JOSESwift a signature that has already been produced, so it only has to assemble the JWS.
private struct PrecomputedDPoPSigner: JOSESwift.SignerProtocol {
	let signature: Data
	let algorithm: JOSESwift.SignatureAlgorithm

	func sign(_ signingInput: Data) throws -> Data { signature }
}
