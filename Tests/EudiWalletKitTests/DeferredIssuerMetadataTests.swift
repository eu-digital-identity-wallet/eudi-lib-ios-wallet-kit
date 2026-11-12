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
import Testing
import OpenID4VCI
import MdocDataModel18013

@testable import EudiWalletKit

extension MetadataCacheTests.DeferredIssuerMetadataTests {
	var issuerURL: String { "https://ec.dev.issuer.eudiw.dev" }

	@Test("The deferred issuer carries the issuer metadata with the request encryption keys")
	func deferredIssuerHasRequestEncryption() async throws {
		let networking = MetadataNetworking(issuerURL: issuerURL)
		let storageService = TestDataStorageService()
		let config = OpenId4VciConfiguration(credentialIssuerURL: issuerURL, clientId: "wallet-dev", requireDpop: false, issuerMetadataPolicy: .ignoreSigned)
		#if canImport(EudiEtsi1196x2)
		let trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef), defaultPolicy: .warning)
		#else
		let trustConfig = TrustConfiguration(rootIaca: [], defaultPolicy: .warning)
		#endif
		let service = try OpenId4VciService(uiCulture: nil, config: config, networking: networking, storage: StorageManager(storageService: storageService), storageService: storageService, trustConfig: trustConfig, localAuthenticationContext: ThreadSafeAuthContext())
		OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
		let endpoint = try JSONDecoder().decode(CredentialIssuerEndpoint.self, from: Data("\"\(issuerURL)/deferred_credential\"".utf8))
		let model = DeferredIssuanceModel(deferredCredentialEndpoint: endpoint, transactionId: try TransactionId(value: "tx-1"), publicKeys: [], derKeyData: nil, timeStamp: 0, interval: nil, dpopKeyId: nil)
		let configuration = CredentialConfiguration(
			configurationIdentifier: try CredentialConfigurationIdentifier(value: "eu.europa.ec.eudi.pid.1"),
			credentialIssuerIdentifier: issuerURL, vct: "urn:eu:europa:ec:eudi:pid:1",
			supportsAttestationProofType: false, supportsJwtProofTypeWithAttestation: false,
			credentialSigningAlgValuesSupported: ["ES256"], dpopSigningAlgValuesSupported: nil, clientAttestationPopSigningAlgValuesSupported: nil,
			issuerDisplay: [], display: [], claims: [], format: .sdjwt,
			defaultCredentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1))

		let issuer = try await service.getIssuerForDeferred(data: model, configuration: configuration)

		let metadata = await issuer.issuerMetadata
		#expect(metadata.deferredCredentialEndpoint?.url.absoluteString == "https://dev.issuer.eudiw.dev/deferred_credential")
		guard case .notRequired(let jwks, _, _) = metadata.credentialRequestEncryption else {
			Issue.record("The deferred issuer has no request encryption keys")
			return
		}
		#expect(!jwks.isEmpty)
	}
}

/// Serves the issuer metadata fixture and a minimal authorization server metadata document.
private actor MetadataNetworking: Networking {
	private let issuerURL: String

	init(issuerURL: String) { self.issuerURL = issuerURL }

	func data(from url: URL) async throws -> (Data, URLResponse) {
		let body: Data
		if url.absoluteString.contains("openid-credential-issuer") {
			body = Data(name: "dev-python-openid-credential-issuer", ext: "json", from: Bundle.module)!
		} else {
			let json = ["issuer": issuerURL, "authorization_endpoint": "\(issuerURL)/authorize", "token_endpoint": "\(issuerURL)/token", "pushed_authorization_request_endpoint": "\(issuerURL)/par", "response_types_supported": ["code"]] as [String: Any]
			body = try JSONSerialization.data(withJSONObject: json)
		}
		let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
		return (body, response)
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		try await data(from: request.url!)
	}
}
