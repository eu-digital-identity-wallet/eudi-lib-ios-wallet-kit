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
import OpenID4VCI
import MdocSecurity18013

public struct OpenId4VCIConfiguration {
	public let client: Client
	public let authFlowRedirectionURI: URL
	public let authorizeIssuanceConfig: AuthorizeIssuanceConfig
	public let usePAR: Bool
	public let cacheIssuerMetadata: Bool

	public init(client: Client? = nil, authFlowRedirectionURI: URL? = nil, authorizeIssuanceConfig: AuthorizeIssuanceConfig = .favorScopes, usePAR: Bool = true, useDPoP: Bool = false, cacheIssuerMetadata: Bool = true) {
		self.client = client ?? .public(id: "wallet-dev")
		self.authFlowRedirectionURI = authFlowRedirectionURI ?? URL(string: "eudi-openid4ci://authorize")!
		self.authorizeIssuanceConfig = authorizeIssuanceConfig
		self.usePAR = usePAR
		self.cacheIssuerMetadata = cacheIssuerMetadata
	}
}

extension OpenId4VCIConfiguration {

	static var supportedDPoPAlgorithms: Set<JWSAlgorithm> {
		[JWSAlgorithm(.ES256), JWSAlgorithm(.ES384), JWSAlgorithm(.ES512), JWSAlgorithm(.RS256)]
	}

	static func makeDPoPConstructor(algorithms: [JWSAlgorithm]?) throws -> DPoPConstructorType? {
		guard let algorithms = algorithms, !algorithms.isEmpty else { return nil }
		let setCommonJwsAlgorithmNames = Array(Set(algorithms.map(\.name)).intersection(Self.supportedDPoPAlgorithms.map(\.name))).sorted()
		guard let algName = setCommonJwsAlgorithmNames.first else {
			throw WalletError(description: "No supported DPoP algorithm found in the provided algorithms \(algorithms.map(\.name)). Supported algorithms are: \(Self.supportedDPoPAlgorithms.map(\.name))")
		}
		let alg = JWSAlgorithm(name: algName)
		logger.info("Signing algorithm for DPoP constructor to be used is: \(alg.name)")
		// EC supported bit sizes are 256, 384, or 521. RS256 is 2048 bits.
		let bits: Int = switch alg.name { case JWSAlgorithm(.ES256).name: 256; case JWSAlgorithm(.ES384).name: 384; case JWSAlgorithm(.ES512).name: 521; case JWSAlgorithm(.RS256).name: 2048; default: throw WalletError(description: "Unsupported DPoP algorithm: \(alg.name)") }
		let type: SecKey.KeyType = switch alg.name { case JWSAlgorithm(.RS256).name: .rsa; default: .ellipticCurve }
		let privateKey = try SecKey.createRandomKey(type: type, bits: bits)
		let publicKey = try KeyController.generateECDHPublicKey(from: privateKey)
		let publicKeyJWK = try ECPublicKey(publicKey: publicKey, additionalParameters: ["alg": alg.name, "use": "sig", "kid": UUID().uuidString])
		let privateKeyProxy: SigningKeyProxy = .secKey(privateKey)
		return DPoPConstructor(algorithm: alg, jwk: publicKeyJWK, privateKey: privateKeyProxy)
	}

	func toOpenId4VCIConfig() -> OpenId4VCIConfig {
		OpenId4VCIConfig(client: client, authFlowRedirectionURI: authFlowRedirectionURI, authorizeIssuanceConfig: authorizeIssuanceConfig, usePAR: usePAR)
	}
}
