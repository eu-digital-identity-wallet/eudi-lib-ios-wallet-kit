import Foundation
import OpenID4VCI
import Testing
@testable import EudiWalletKit

@Suite(.serialized)
struct AuthorizationServerMetadataCacheTests {
    @Test func reusesMetadataPerServerUntilIssuerCacheIsCleared() async throws {
        OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
        defer { OpenId4VciService.clearIssuerAndAuthorizationMetadataCache() }
        let networking = AuthorizationMetadataNetworking()
        let first = URL(string: "https://authorization.example/first")!
        let second = URL(string: "https://authorization.example/second")!

        for server in [first, first, second] {
            let metadata = try await OpenId4VciService.resolveAuthorizationServerMetadata(url: server, networking: networking)
            guard case .oauth(let oauth) = metadata else {
                Issue.record("Expected OAuth metadata")
                return
            }
            #expect(oauth.issuer == server.absoluteString)
            #expect(oauth.tokenEndpoint == server.appendingPathComponent("token").absoluteString)
        }
        #expect(await networking.requestCount == 2)

        OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
        _ = try await OpenId4VciService.resolveAuthorizationServerMetadata(url: first, networking: networking)
        #expect(await networking.requestCount == 3)
    }

    @Test func failedResolutionIsRetried() async throws {
        OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
        defer { OpenId4VciService.clearIssuerAndAuthorizationMetadataCache() }
        let networking = AuthorizationMetadataNetworking(failRequests: true)
        let server = URL(string: "https://authorization.example/retry")!
        await #expect(throws: (any Error).self) {
            try await OpenId4VciService.resolveAuthorizationServerMetadata(url: server, networking: networking)
        }
        await networking.allowRequests()
        let metadata = try await OpenId4VciService.resolveAuthorizationServerMetadata(url: server, networking: networking)
        guard case .oauth(let oauth) = metadata else {
            Issue.record("Expected OAuth metadata after retry")
            return
        }
        #expect(oauth.issuer == server.absoluteString)
        #expect(await networking.requestCount == 3) // Failed OAuth and OIDC discovery, then successful OAuth discovery.
    }
}

private actor AuthorizationMetadataNetworking: Networking {
    private(set) var requestCount = 0
    private var failRequests: Bool

    init(failRequests: Bool = false) {
        self.failRequests = failRequests
    }

    func allowRequests() {
        failRequests = false
    }

    func data(from url: URL) async throws -> (Data, URLResponse) {
        requestCount += 1
        if failRequests { throw URLError(.cannotConnectToHost) }
        let server = url.absoluteString.replacingOccurrences(of: "/.well-known/oauth-authorization-server", with: "")
        let metadata = AuthorizationServerMetadata(issuer: server, tokenEndpoint: server + "/token")
        let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
        return (try JSONEncoder().encode(metadata), response)
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await data(from: #require(request.url))
    }
}
