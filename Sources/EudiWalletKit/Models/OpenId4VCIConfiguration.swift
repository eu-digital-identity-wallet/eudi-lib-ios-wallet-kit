
/*
Copyright (c) 2026 European Commission

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
import Copyable
import CryptoKit
import JOSESwift
import MdocDataModel18013
import MdocSecurity18013
import OpenID4VCI
import Security
import SwiftyJSON

@Copyable
public struct OpenId4VciConfiguration: Sendable {
	/// The URL of the credential issuer
	public let credentialIssuerURL: String?
	/// The client identifier used for OpenID4VCI flows
	public let clientId: String
	/// Configuration for key attestation, if supported by the issuer
	public let keyAttestationsConfig: KeyAttestationConfiguration
	/// The redirect URI used after authorization flow completion
	public let authFlowRedirectionURI: URL
	/// Configuration that determines how authorization issuance should be handled
	public let authorizeIssuanceConfig: AuthorizeIssuanceConfig
	/// Whether to use Pushed Authorization Request (PAR) for enhanced security
	public let parUsage: ParUsage
	/// Whether to require DPoP (Demonstrating Proof-of-Possession)
	public let requireDpop: Bool
	/// Policy for handling signed issuer metadata fetched from `/.well-known/openid-credential-issuer`.
	///
	/// - `.ignoreSigned` (default): wallet sends `Accept: application/json` and only accepts plain JSON metadata. Backwards-compatible with all existing deployments.
	/// - `.preferSigned(issuerTrust:)`: wallet sends `Accept: application/jwt, application/json`. If the issuer returns a signed JWT, the signature is verified against the supplied trust anchor; otherwise plain JSON is accepted as a fallback.
	/// - `.requireSigned(issuerTrust:)`: wallet sends `Accept: application/jwt`. The issuer must return a signed JWT whose signature validates against the supplied trust anchor; plain JSON responses are rejected.
	public let issuerMetadataPolicy: IssuerMetadataPolicy
	/// Whether user authentication is required for credential issuance
	public let userAuthenticationRequired: Bool
	/// Key options for generating DPoP keys, if DPoP is used
	public let dpopKeyOptions: KeyOptions?

	public init(
		credentialIssuerURL: String?,
		clientId: String? = nil,
		keyAttestationsConfig: KeyAttestationConfiguration,
		authFlowRedirectionURI: URL? = nil,
		authorizeIssuanceConfig: AuthorizeIssuanceConfig = .favorScopes,
		parUsage: ParUsage = .required(authorizationCodeDPoPBinding: true),
		requireDpop: Bool = true,
		issuerMetadataPolicy: IssuerMetadataPolicy = .ignoreSigned,
		cacheIssuerMetadata: Bool = true,
		userAuthenticationRequired: Bool = false,
		dpopKeyOptions: KeyOptions? = nil,
		trustedIssuerCertificates: [x5chain]? = nil
	) {
		self.credentialIssuerURL = credentialIssuerURL
		self.clientId = clientId ?? "eudiw-abca"
		self.keyAttestationsConfig = keyAttestationsConfig
		self.authFlowRedirectionURI = authFlowRedirectionURI ?? URL(string: "eudi-openid4ci://authorize")!
		self.authorizeIssuanceConfig = authorizeIssuanceConfig
		self.parUsage = parUsage
		self.requireDpop = requireDpop
		self.issuerMetadataPolicy = issuerMetadataPolicy
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

	/// Creates a PoP constructor based on the provided parameters and configuration.
	func makePoPConstructor(popUsage: PopUsage, privateKeyId: String?, algorithms: [JWSAlgorithm]?, keyOptions: KeyOptions?) async throws -> DPoPConstructor? {
		guard let algorithms = algorithms, !algorithms.isEmpty else { return nil }
		let signingKeyProxy: SigningKeyProxy
		let publicKey: SecKey
		let jwsAlgorithm: JWSAlgorithm
		let jwk: any JWK
		let keyId = privateKeyId ?? UUID().uuidString
		logger.info("Constructing POP for keyId: \(keyId), usage: \(popUsage)")
		if let keyOptions {
			// If keyOptions is specified, use it to determine key generation parameters
			let secureArea = SecureAreaRegistry.shared.get(name: keyOptions.secureAreaName)
			let ecCurve = keyOptions.curve
			let ecAlgorithm = await secureArea.defaultSigningAlgorithm(ecCurve: keyOptions.curve)
			guard let jwsAlg = ecCurve.jwsAlgorithm, algorithms.map(\.name).contains(jwsAlg.name) else {
				throw WalletError(description: "Specified algorithm \(ecCurve.SECGName) not supported by server supported algorithms \(algorithms.map(\.name))", code: .unsupportedAlgorithm)
			}
			jwsAlgorithm = jwsAlg
			let existingKeyInfo: KeyBatchInfo? = if let privateKeyId { try? await secureArea.getKeyBatchInfo(id: privateKeyId) } else { nil }
			let hasCompatibleExistingKey = existingKeyInfo != nil && keyOptions.secureAreaName == existingKeyInfo?.secureAreaName && keyOptions.curve == ecCurve && existingKeyInfo?.usedCounts.count == 1
			let existingPublicKey: CoseKey? = if hasCompatibleExistingKey, let privateKeyId { try? await secureArea.getPublicKey(id: privateKeyId, index: 0, curve: ecCurve) } else { nil }
			if hasCompatibleExistingKey, let privateKeyId, existingPublicKey == nil { try await secureArea.deleteKeyInfo(id: privateKeyId) }
			let publicCoseKey: CoseKey =
				if let existingPublicKey { existingPublicKey } else {
					(try await secureArea.createKeyBatch(id: keyId, credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1), keyOptions: keyOptions)).first!
				}
			let publicKeyJwk = try publicCoseKey.jwk
			let unlockData = try await secureArea.unlockKey(id: keyId)
			let signer = try SecureAreaSigner(secureArea: secureArea, id: keyId, index: 0, publicKey: publicKeyJwk.toJoseSwiftJWK(), curve: ecCurve, ecAlgorithm: ecAlgorithm, unlockData: unlockData)
			signingKeyProxy = .custom(signer)
			publicKey = try publicCoseKey.toSecKey()
		} else {
			let setCommonJwsAlgorithmNames = Array(Set(algorithms.map(\.name)).intersection(Self.supportedDPoPAlgorithms.map(\.name))).sorted()
			guard let algName = setCommonJwsAlgorithmNames.first else {
				let serverAlgorithms = algorithms.map(\.name)
				let walletAlgorithms = Self.supportedDPoPAlgorithms.map(\.name)
				throw WalletError(description: "No wallet supported DPoP algorithm found in the server supported algorithms \(serverAlgorithms). Wallet supported algorithms are: \(walletAlgorithms)", code: .unsupportedAlgorithm)
			}
			jwsAlgorithm = JWSAlgorithm(name: algName)
			logger.info("Signing algorithm for DPoP constructor to be used is: \(jwsAlgorithm.name)")
			// EC supported bit sizes are 256, 384, or 521. RS256 is 2048 bits.
			let bits: Int =
				switch jwsAlgorithm.name {
				case JWSAlgorithm(.ES256).name: 256
				case JWSAlgorithm(.ES384).name: 384
				case JWSAlgorithm(.ES512).name: 521
				case JWSAlgorithm(.RS256).name: 2048
				default: throw WalletError(description: "Unsupported DPoP algorithm: \(jwsAlgorithm.name)", code: .unsupportedAlgorithm)
				}
			let type: SecKey.KeyType =
				switch jwsAlgorithm.name {
				case JWSAlgorithm(.RS256).name: .rsa
				default: .ellipticCurve
				}
			let privateKey: SecKey = if let privateKeyId, let pk = SecKey.getExistingKey(type: type, keyId: privateKeyId) { pk } else { try SecKey.createRandomKey(type: type, bits: bits, keyId: privateKeyId) }
			signingKeyProxy = .secKey(privateKey)
			publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		}
		if jwsAlgorithm.name.starts(with: "RS") {
			jwk = try RSAPublicKey(publicKey: publicKey, additionalParameters: ["alg": jwsAlgorithm.name, "use": "sig", "kid": keyId])
		} else {
			jwk = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": jwsAlgorithm.name, "use": "sig", "kid": keyId])
		}
		return DPoPConstructor(algorithm: jwsAlgorithm, jwk: jwk, privateKey: signingKeyProxy)
	}
	
	static let supportedCredentialReusePolicies: SupportedCredentialReusePolicies = .supported([.limitedTime, .onceOnly, .rotatingBatch])

	func toOpenId4VCIConfig(credentialIssuerId: String, clientAttestationPopSigningAlgValuesSupported: [JWSAlgorithm]) async throws -> OpenId4VCIConfig {
		let client: Client = try await makeAttestationClient(config: keyAttestationsConfig, credentialIssuerId: credentialIssuerId, algorithms: clientAttestationPopSigningAlgValuesSupported)
		let clientAttestationPoPBuilder: ClientAttestationPoPBuilder = DefaultClientAttestationPoPBuilder()
		return OpenId4VCIConfig(client: client, authFlowRedirectionURI: authFlowRedirectionURI, authorizeIssuanceConfig: authorizeIssuanceConfig, requirePAR: parUsage, clientAttestationPoPBuilder: clientAttestationPoPBuilder, issuerMetadataPolicy: issuerMetadataPolicy, requireDpop: requireDpop, supportedCredentialReusePolicies: Self.supportedCredentialReusePolicies)
	}

	private func makeAttestationClient(config: KeyAttestationConfiguration, credentialIssuerId: String, algorithms: [JWSAlgorithm]?) async throws -> Client {
		let keyId = generatePopKeyId(credentialIssuerId: credentialIssuerId)
		guard let popConstructor = try await makePoPConstructor(popUsage: .clientAttestation, privateKeyId: keyId, algorithms: algorithms, keyOptions: config.popKeyOptions) else {
			throw WalletError(description: "Failed to create DPoP constructor for client attestation", code: .internalError)
		}
		let signingKey = popConstructor.privateKey
		let attestationsProvider = config.walletAttestationsProvider
		guard let signatureAlgorithm = SignatureAlgorithm(rawValue: popConstructor.algorithm.name) else {
			throw WalletError(description: "Unsupported DPoP algorithm: \(popConstructor.algorithm.name) for client attestation", code: .unsupportedAlgorithm)
		}
		let popJwtSpec = try ClientAttestationPoPJWTSpec(signingAlgorithm: signatureAlgorithm, duration: config.popKeyDuration ?? 300.0, typ: "oauth-client-attestation-pop+jwt")
		let client: Client = .attested(id: clientId, alg: popConstructor.algorithm, jwk: popConstructor.jwk, popJwtSpec: popJwtSpec, clientAttestationProvider: { _ in
			let attestation = try await attestationsProvider.getWalletAttestation(signingKey: signingKey)
			return (try ClientAttestationJWT(jws: JWS(compactSerialization: attestation)), signingKey)
		})
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
