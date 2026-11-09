import Testing
import Foundation
import OpenID4VCI
import JOSESwift
import MdocDataModel18013
@testable import EudiWalletKit

@Suite("Resume pending issuance DPoP nonce")
struct ResumePendingIssuanceDPoPNonceTests {

	private static let tokenEndpoint = URL(string: "https://issuer.example/token")!
	private static let state = "state-123"

	@Test func forwardsTheFinishAuthorizationNonceToTheFirstTokenRequest() async throws {
		let networking = TokenEndpointStub(responses: [.success])
		let request = try OpenId4VciService.makeResumeAuthorizationRequest(model: makePendingModel(), authorizePresentationUrl: Self.authorizeUrl, nonce: "finish-authorization-nonce")

		_ = try await authorize(request: request, networking: networking)

		let proofs = await networking.dpopProofs
		#expect(proofs.count == 1)
		#expect(try nonceClaim(of: try #require(proofs.first)) == "finish-authorization-nonce")
	}

	@Test func withoutANonceTheLibraryStillRetriesWithTheServerNonce() async throws {
		let networking = TokenEndpointStub(responses: [.useDpopNonce("server-nonce"), .success])
		let request = try OpenId4VciService.makeResumeAuthorizationRequest(model: makePendingModel(), authorizePresentationUrl: Self.authorizeUrl, nonce: nil)

		_ = try await authorize(request: request, networking: networking)

		let proofs = await networking.dpopProofs
		#expect(proofs.count == 2)
		#expect(try nonceClaim(of: proofs[0]) == nil)
		#expect(try nonceClaim(of: proofs[1]) == "server-nonce")
	}

	private static let authorizeUrl = "https://issuer.example/authorize?client_id=wallet&request_uri=urn:example"

	private func authorize(request: AuthorizationRequested, networking: TokenEndpointStub) async throws -> AuthorizedRequest {
		let issuer = try await makeIssuer(networking: networking)
		return try await issuer.authorizeWithAuthorizationCode(
			serverState: Self.state,
			request: request,
			authorizationCode: try AuthorizationCode(value: "auth-code"),
			authorizationDetailsInTokenRequest: .doNotInclude,
			grant: .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil))
		)
	}

	private func makeIssuer(networking: TokenEndpointStub) async throws -> Issuer {
		let metadataData = try #require(Data(name: "pid-demo-openid-credential-issuer", ext: "json", from: Bundle.module))
		let issuerMetadata = try JSONDecoder().decode(CredentialIssuerMetadata.self, from: metadataData)
		let authorizationServerMetadata = AuthorizationServerMetadata(
			issuer: "https://issuer.example",
			authorizationEndpoint: "https://issuer.example/authorize",
			tokenEndpoint: Self.tokenEndpoint.absoluteString,
			dpopSigningAlgValuesSupported: [JWSAlgorithm(.ES256)]
		)
		let vciConfig = try await OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example", clientId: "wallet")
			.toOpenId4VCIConfig(credentialIssuerId: "https://issuer.example", clientAttestationPopSigningAlgValuesSupported: nil, context: ThreadSafeAuthContext())

		let privateKey = try #require(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256] as CFDictionary, nil))
		let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
		let dpopConstructor = DPoPConstructor(algorithm: JWSAlgorithm(.ES256), jwk: try ECPublicKey(publicKey: publicKey), privateKey: .secKey(privateKey))

		return try Issuer(
			authorizationServerMetadata: .oauth(authorizationServerMetadata),
			issuerMetadata: issuerMetadata,
			config: vciConfig,
			parPoster: Poster(session: networking),
			tokenPoster: Poster(session: networking),
			dpopConstructor: dpopConstructor
		)
	}

	private func makePendingModel() throws -> PendingIssuanceModel {
		PendingIssuanceModel(
			pendingReason: .presentation_request_url(Self.authorizeUrl),
			configuration: CredentialConfiguration(
				configurationIdentifier: try CredentialConfigurationIdentifier(value: "pid-sd-jwt"),
				credentialIssuerIdentifier: "https://issuer.example",
				vct: "urn:eudi:pid:de:1",
				supportsAttestationProofType: true,
				supportsJwtProofTypeWithAttestation: true,
				credentialSigningAlgValuesSupported: ["ES256"],
				dpopSigningAlgValuesSupported: ["ES256"],
				clientAttestationPopSigningAlgValuesSupported: nil,
				issuerDisplay: [],
				display: [],
				claims: [],
				format: .sdjwt,
				defaultCredentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1)
			),
			metadataKey: "https://issuer.example",
			pckeCodeVerifier: "code-verifier-0123456789012345678901234567890123",
			pckeCodeVerifierMethod: "S256",
			state: Self.state
		)
	}

	private func nonceClaim(of proof: String) throws -> String? {
		let segments = proof.split(separator: ".")
		try #require(segments.count == 3)
		var payload = String(segments[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
		payload += String(repeating: "=", count: (4 - payload.count % 4) % 4)
		let data = try #require(Data(base64Encoded: payload))
		let claims = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
		return claims["nonce"] as? String
	}
}

private actor TokenEndpointStub: Networking {
	enum Response {
		case success
		case useDpopNonce(String)
	}

	private var responses: [Response]
	private(set) var dpopProofs: [String] = []

	init(responses: [Response]) {
		self.responses = responses
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		throw URLError(.unsupportedURL)
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		let url = try #require(request.url)
		if let proof = request.value(forHTTPHeaderField: "DPoP") {
			dpopProofs.append(proof)
		}
		switch responses.isEmpty ? .success : responses.removeFirst() {
		case .success:
			let body = #"{"access_token":"access-token","token_type":"DPoP","expires_in":3600,"refresh_token":"refresh-token"}"#
			return (Data(body.utf8), HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!)
		case .useDpopNonce(let nonce):
			let body = #"{"error":"use_dpop_nonce"}"#
			let headers = ["Content-Type": "application/json", "WWW-Authenticate": #"DPoP error="use_dpop_nonce""#, "DPoP-Nonce": nonce]
			return (Data(body.utf8), HTTPURLResponse(url: url, statusCode: 401, httpVersion: nil, headerFields: headers)!)
		}
	}
}
