/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import Foundation
import JOSESwift
import SwiftyJSON
import OpenID4VCI
import MdocDataModel18013
import MdocSecurity18013
import CryptoKit

public struct OpenId4VciConfiguration: Sendable {
	public let credentialIssuerURL: String?
	public let clientId: String
	public let keyAttestationsConfig: KeyAttestationConfig?
	public let authFlowRedirectionURI: URL
	public let authorizeIssuanceConfig: AuthorizeIssuanceConfig
	public let usePAR: Bool
	public let useDpopIfSupported: Bool
	public let cacheIssuerMetadata: Bool
	public let userAuthenticationRequired: Bool
	public let dpopKeyOptions: KeyOptions?

	public init(credentialIssuerURL: String?, clientId: String? = nil, keyAttestationsConfig: KeyAttestationConfig? = nil, authFlowRedirectionURI: URL? = nil, authorizeIssuanceConfig: AuthorizeIssuanceConfig = .favorScopes, usePAR: Bool = true, useDpopIfSupported: Bool = true, cacheIssuerMetadata: Bool = true, userAuthenticationRequired: Bool = false, dpopKeyOptions: KeyOptions? = nil) {
		self.credentialIssuerURL = credentialIssuerURL
		self.clientId = clientId ?? "wallet-dev"
		self.keyAttestationsConfig = keyAttestationsConfig
		self.authFlowRedirectionURI = authFlowRedirectionURI ?? URL(string: "eudi-openid4ci://authorize")!
		self.authorizeIssuanceConfig = authorizeIssuanceConfig
		self.usePAR = usePAR
		self.useDpopIfSupported = useDpopIfSupported
		self.cacheIssuerMetadata = cacheIssuerMetadata
		self.userAuthenticationRequired = userAuthenticationRequired
		self.dpopKeyOptions = dpopKeyOptions
	}
}

extension CoseEcCurve {
	var jwsAlgorithm: JWSAlgorithm? {
		switch self {
		case .P256: JWSAlgorithm(.ES256)
		case .P384: JWSAlgorithm(.ES384)
		case .P521: JWSAlgorithm(.ES512)
		default: nil
		}
	}
}

extension OpenId4VciConfiguration {

	static var supportedDPoPAlgorithms: Set<JWSAlgorithm> {
		[JWSAlgorithm(.ES256), JWSAlgorithm(.ES384), JWSAlgorithm(.ES512), JWSAlgorithm(.RS256)]
	}

	func makeDPoPConstructor(keyId dpopKeyId: String?, algorithms: [JWSAlgorithm]?) async throws -> DPoPConstructor? {
		guard let algorithms = algorithms, !algorithms.isEmpty else { return nil }
		let privateKeyProxy: SigningKeyProxy
		let publicKey: SecKey
		let jwsAlgorithm: JWSAlgorithm
		let jwk: any JWK
		let keyId = dpopKeyId ?? UUID().uuidString
		if let dpopKeyOptions {
			// If dpopKeyOptions is specified, use it to determine key generation parameters
			let secureArea = SecureAreaRegistry.shared.get(name: dpopKeyOptions.secureAreaName)
			let ecCurve = dpopKeyOptions.curve
			let ecAlgorithm = await secureArea.defaultSigningAlgorithm(ecCurve: dpopKeyOptions.curve)
			guard let jwsAlg = ecCurve.jwsAlgorithm, algorithms.map(\.name).contains(jwsAlg.name) else {
				throw WalletError(description: "Specified algorithm \(ecCurve.SECGName) not supported by server supported algorithms \(algorithms.map(\.name))") }
			jwsAlgorithm = jwsAlg
			let publicCoseKey: CoseKey = if let dpopKeyId, !dpopKeyId.hasSuffix("_dpop"), let keyInfo = try? await secureArea.getKeyBatchInfo(id: dpopKeyId), dpopKeyOptions.secureAreaName == keyInfo.secureAreaName, dpopKeyOptions.curve == ecCurve, keyInfo.usedCounts.count == 1, let pck = try? await secureArea.getPublicKey(id: dpopKeyId, index: 0, curve: ecCurve) { pck } else {
				(try await secureArea.createKeyBatch(id: keyId, credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1), keyOptions: dpopKeyOptions)).first! }
			let unlockData = try await secureArea.unlockKey(id: keyId)
			let signer = try SecureAreaSigner(secureArea: secureArea, id: keyId, index: 0, ecAlgorithm: ecAlgorithm, unlockData: unlockData)
			privateKeyProxy = .custom(signer)
			publicKey = try publicCoseKey.toSecKey()
		} else {
			let setCommonJwsAlgorithmNames = Array(Set(algorithms.map(\.name)).intersection(Self.supportedDPoPAlgorithms.map(\.name))).sorted()
			guard let algName = setCommonJwsAlgorithmNames.first else {
				throw WalletError(description: "No wallet supported DPoP algorithm found in the server supported algorithms \(algorithms.map(\.name)). Wallet supported algorithms are: \(Self.supportedDPoPAlgorithms.map(\.name))")
			}
			jwsAlgorithm = JWSAlgorithm(name: algName)
			logger.info("Signing algorithm for DPoP constructor to be used is: \(jwsAlgorithm.name)")
			// EC supported bit sizes are 256, 384, or 521. RS256 is 2048 bits.
			let bits: Int = switch jwsAlgorithm.name { case JWSAlgorithm(.ES256).name: 256; case JWSAlgorithm(.ES384).name: 384; case JWSAlgorithm(.ES512).name: 521; case JWSAlgorithm(.RS256).name: 2048; default: throw WalletError(description: "Unsupported DPoP algorithm: \(jwsAlgorithm.name)") }
			let type: SecKey.KeyType = switch jwsAlgorithm.name { case JWSAlgorithm(.RS256).name: .rsa; default: .ellipticCurve }
			let privateKey: SecKey = if let dpopKeyId, !dpopKeyId.hasSuffix("_dpop"), let pk = SecKey.getExistingKey(type: type, keyId: dpopKeyId) { pk } else { try SecKey.createRandomKey(type: type, bits: bits, keyId: dpopKeyId) }
			privateKeyProxy = .secKey(privateKey)
			publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		}
		if jwsAlgorithm.name.starts(with: "RS") {
			jwk = try RSAPublicKey(publicKey: publicKey, additionalParameters: ["alg": jwsAlgorithm.name, "use": "sig", "kid": keyId])
		} else {
			jwk = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": jwsAlgorithm.name, "use": "sig", "kid": keyId])
		}
		return DPoPConstructor(algorithm: jwsAlgorithm, jwk: jwk, privateKey: privateKeyProxy)
	}

	func toOpenId4VCIConfig(credentialIssuerId: String, clientAttestationPopSigningAlgValuesSupported: [JWSAlgorithm]?) async throws -> OpenId4VCIConfig {
		let client: Client = if let keyAttestationsConfig, clientAttestationPopSigningAlgValuesSupported != nil { try await makeAttestationClient(config: keyAttestationsConfig, credentialIssuerId: credentialIssuerId, algorithms: clientAttestationPopSigningAlgValuesSupported) } else { .public(id: clientId) }
		let clientAttestationPoPBuilder: ClientAttestationPoPBuilder? = if keyAttestationsConfig != nil { DefaultClientAttestationPoPBuilder() } else { nil}
		return OpenId4VCIConfig(client: client, authFlowRedirectionURI: authFlowRedirectionURI, authorizeIssuanceConfig: authorizeIssuanceConfig, usePAR: usePAR, clientAttestationPoPBuilder: clientAttestationPoPBuilder, useDpopIfSupported: useDpopIfSupported)
	}

	private func makeAttestationClient(config: KeyAttestationConfig, credentialIssuerId: String, algorithms: [JWSAlgorithm]?) async throws -> Client {
		let keyId = generatePopKeyId(credentialIssuerId: credentialIssuerId)
		guard let dpopConstructor = try await makeDPoPConstructor(keyId: keyId, algorithms: algorithms) else {	 throw WalletError(description: "Failed to create DPoP constructor for client attestation") }
		let attestation = try await config.walletAttestationsProvider.getWalletAttestation(key: dpopConstructor.jwk)
		guard let signatureAlgorithm = SignatureAlgorithm(rawValue: dpopConstructor.algorithm.name) else {
			throw WalletError(description: "Unsupported DPoP algorithm: \(dpopConstructor.algorithm.name) for client attestation")
		}
		let popJwtSpec = try ClientAttestationPoPJWTSpec(signingAlgorithm: signatureAlgorithm, duration: config.popKeyDuration ?? 300.0, typ: "oauth-client-attestation-pop+jwt", signingKey: dpopConstructor.privateKey)
		let client: Client = .attested(attestationJWT: try .init(jws: .init(compactSerialization: attestation)), popJwtSpec: popJwtSpec)
		return client
	}

		/// Generates a deterministic key alias based on the CredentialIssuerId.
	///
	/// This ensures the same key is reused for the same issuer across sessions. The alias is
	/// generated by:
	/// 1. Creating a SHA-256 hash of the issuer ID
	/// 2. Converting the hash to hex format
	/// 3. Truncating to 16 characters for a compact, URL-safe identifier
	/// 4. Prefixing with "client-attestation-" for namespace clarity
	///
	/// - Parameter credentialIssuerId: The credential issuer identifier to hash
	/// - Returns: A deterministic, stable key alias for the given issuer
	private func generatePopKeyId(credentialIssuerId: String) -> String {
		// Create a hash of the issuer ID to get a stable, URL-safe identifier
		let data = Data(credentialIssuerId.utf8)
		let hash = SHA256.hash(data: data)
		let hashHex = hash.map { String(format: "%02x", $0) }.joined().prefix(16)
		return "client-attestation-\(hashHex)"
	}
}
