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
import MdocDataModel18013
import OpenID4VCI
import Testing
@testable import EudiWalletKit

/// Run these stress tests with Thread Sanitizer for data-race diagnostics:
/// `swift test --sanitize thread --filter MetadataCacheConcurrencyTests`.
/// The default CI lane runs without TSan and only checks observable behavior;
/// these stress tests alone do not reliably detect a race in an unprotected cache.
extension MetadataCacheTests.MetadataCacheConcurrencyTests {
    @Test("Separate issuer services can resolve metadata while both caches are cleared")
    func concurrentIssuerResolutionAndClearing() async throws {
        OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
        defer { OpenId4VciService.clearIssuerAndAuthorizationMetadataCache() }
        let networking = ConcurrentMetadataNetworking()

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                for _ in 0..<256 {
                    OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
                    await Task.yield()
                }
            }
            for index in 0..<32 {
                group.addTask {
                    let issuer = "https://issuer-\(index).cache-test.example"
                    let service = try makeService(issuer: issuer, networking: networking)
                    for _ in 0..<16 {
                        let (identifier, metadata) = try await service.resolveIssuerMetadata()
                        #expect(identifier.url.absoluteString == issuer)
                        #expect(metadata.credentialIssuerIdentifier == identifier)
                        #expect(metadata.credentialEndpoint.url.absoluteString == issuer + "/credential")
                        await Task.yield()
                    }
                }
            }
            try await group.waitForAll()
        }
    }

    @Test("Authorization metadata stays associated with its server during concurrent reads, writes and clears")
    func concurrentAuthorizationResolutionAndClearing() async throws {
        OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
        defer { OpenId4VciService.clearIssuerAndAuthorizationMetadataCache() }
        let networking = ConcurrentMetadataNetworking()

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                for _ in 0..<256 {
                    OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
                    await Task.yield()
                }
            }
            for index in 0..<32 {
                group.addTask {
                    let server = URL(string: "https://authorization-\(index).cache-test.example")!
                    for _ in 0..<16 {
                        let metadata = try await OpenId4VciService.resolveAuthorizationServerMetadata(url: server, networking: networking)
                        guard case .oauth(let oauth) = metadata else {
                            Issue.record("Expected OAuth metadata")
                            return
                        }
                        #expect(oauth.issuer == server.absoluteString)
                        #expect(oauth.tokenEndpoint == server.absoluteString + "/token")
                        await Task.yield()
                    }
                }
            }
            try await group.waitForAll()
        }
    }

    @Test("Issuer and authorization metadata are reused and cleared together")
    func reuseAndClearBothCaches() async throws {
        OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
        defer { OpenId4VciService.clearIssuerAndAuthorizationMetadataCache() }
        let networking = ConcurrentMetadataNetworking()
        let issuer = "https://reuse.cache-test.example"
        let server = URL(string: issuer)!
        let service = try makeService(issuer: issuer, networking: networking)

        for _ in 0..<2 {
            _ = try await service.resolveIssuerMetadata()
            _ = try await OpenId4VciService.resolveAuthorizationServerMetadata(url: server, networking: networking)
        }
        #expect(await networking.requestCount == 2)

        OpenId4VciService.clearIssuerAndAuthorizationMetadataCache()
        _ = try await service.resolveIssuerMetadata()
        _ = try await OpenId4VciService.resolveAuthorizationServerMetadata(url: server, networking: networking)
        #expect(await networking.requestCount == 4)
    }
}

private func makeService(issuer: String, networking: any Networking) throws -> OpenId4VciService {
    let storage = TestDataStorageService()
    #if canImport(EudiEtsi1196x2)
    let trust = TrustConfiguration(trustSource: .etsi(.eudiRef), defaultPolicy: .warning)
    #else
    let trust = TrustConfiguration(rootIaca: [], defaultPolicy: .warning)
    #endif
    return try OpenId4VciService(
        uiCulture: nil,
        config: OpenId4VciConfiguration(credentialIssuerURL: issuer, clientId: "cache-test", requireDpop: false),
        networking: networking,
        storage: StorageManager(storageService: storage),
        storageService: storage,
        trustConfig: trust,
        localAuthenticationContext: ThreadSafeAuthContext()
    )
}

/// Only synthetic metadata is served; no external issuer, keys or user credentials are needed.
private actor ConcurrentMetadataNetworking: Networking {
    private(set) var requestCount = 0

    func data(from url: URL) async throws -> (Data, URLResponse) {
        requestCount += 1
        let origin = "https://\(try #require(url.host))"
        let body: Data
        if url.path.contains("openid-credential-issuer") {
            body = Data("""
            {
                "credential_issuer": "\(origin)",
                "credential_endpoint": "\(origin)/credential",
                "credential_configurations_supported": {
                    "example": {"format": "dc+sd-jwt", "vct": "urn:example:cache-test"}
                }
            }
            """.utf8)
        } else {
            let metadata = AuthorizationServerMetadata(issuer: origin, tokenEndpoint: origin + "/token")
            body = try JSONEncoder().encode(metadata)
        }
        let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
        await Task.yield()
        return (body, response)
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        try await data(from: #require(request.url))
    }
}
