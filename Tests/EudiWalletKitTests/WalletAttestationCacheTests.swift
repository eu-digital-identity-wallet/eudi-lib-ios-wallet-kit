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
import Security
import os
import Testing
@preconcurrency import JOSESwift
import OpenID4VCI

@testable import EudiWalletKit

@Suite("Wallet attestation expiry")
struct WalletAttestationCacheTests {
    @Test("A valid cached WIA is reused")
    func reuse() async throws {
        let key = try KeyController.generateECDHPrivateKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let jwt = try token(key: key, expiry: now.addingTimeInterval(60))
        let provider = ExpiryTestProvider(responses: [.success(jwt)], expectedKey: .secKey(key))
        let cache = WalletAttestationCache(provider: provider, signingKey: .secKey(key), clock: ExpiryTestClock(now))
        #expect(try await cache.attestation().value == jwt)
        #expect(try await cache.attestation().value == jwt)
        #expect(await provider.calls == 1)
    }

    @Test("Expiry renews the WIA with the same signing key, including concurrent callers")
    func refresh() async throws {
        let key = try KeyController.generateECDHPrivateKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let clock = ExpiryTestClock(now)
        let original = try token(key: key, expiry: now.addingTimeInterval(60))
        let renewed = try token(key: key, expiry: now.addingTimeInterval(120))
        let provider = ExpiryTestProvider(responses: [.success(original), .success(renewed)], expectedKey: .secKey(key))
        let cache = WalletAttestationCache(provider: provider, signingKey: .secKey(key), clock: clock)
        #expect(try await cache.attestation().value == original)
        clock.set(now.addingTimeInterval(60))
        let values = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<10 {
                group.addTask { try await cache.attestation().value }
            }
            var values: [String] = []
            for try await value in group { values.append(value) }
            return values
        }
        #expect(values.count == 10)
        #expect(values.allSatisfy { $0 == renewed })
        #expect(await provider.calls == 2)
        #expect(await provider.usedExpectedKey)
    }

    @Test("A failed refresh propagates its error and a later call can retry")
    func refreshFailure() async throws {
        let key = try KeyController.generateECDHPrivateKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let clock = ExpiryTestClock(now)
        let original = try token(key: key, expiry: now.addingTimeInterval(60))
        let renewed = try token(key: key, expiry: now.addingTimeInterval(120))
        let provider = ExpiryTestProvider(
            responses: [.success(original), .failure(.unavailable), .success(renewed)], expectedKey: .secKey(key)
        )
        let cache = WalletAttestationCache(provider: provider, signingKey: .secKey(key), clock: clock)
        #expect(try await cache.attestation().value == original)
        clock.set(now.addingTimeInterval(60))
        await #expect(throws: ExpiryTestError.unavailable) { try await cache.attestation() }
        #expect(try await cache.attestation().value == renewed)
        #expect(await provider.calls == 3)
    }

    @Test("An expired or malformed provider result is rejected and never cached")
    func invalidResponse() async throws {
        let key = try KeyController.generateECDHPrivateKey()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let expired = try token(key: key, expiry: now)
        let valid = try token(key: key, expiry: now.addingTimeInterval(60))
        for invalid in [expired, "malformed-jwt", try token(key: key, expiry: nil)] {
            let provider = ExpiryTestProvider(responses: [.success(invalid), .success(valid)], expectedKey: .secKey(key))
            let cache = WalletAttestationCache(provider: provider, signingKey: .secKey(key), clock: ExpiryTestClock(now))
            await #expect(throws: (any Error).self) { try await cache.attestation() }
            #expect(try await cache.attestation().value == valid)
            #expect(await provider.calls == 2)
        }
    }

    private func token(key: SecKey, expiry: Date?) throws -> String {
        var claims: [String: Any] = ["iss": "provider", "sub": "client"]
        if let expiry { claims["exp"] = expiry.timeIntervalSince1970 }
        let header = try JWSHeader(parameters: ["alg": "ES256", "typ": "oauth-client-attestation+jwt"])
        let payload = Payload(try JSONSerialization.data(withJSONObject: claims))
        let signer = try #require(Signer(signatureAlgorithm: .ES256, key: key))
        return try JWS(header: header, payload: payload, signer: signer).compactSerializedString
    }
}

private final class ExpiryTestClock: ClockType {
    private let instant: OSAllocatedUnfairLock<Date>
    init(_ date: Date) { instant = OSAllocatedUnfairLock(initialState: date) }
    func now() -> Date { instant.withLock { $0 } }
    func set(_ date: Date) { instant.withLock { $0 = date } }
}

private enum ExpiryTestError: Error, Equatable {
    case unavailable
}

private actor ExpiryTestProvider: WalletAttestationsProvider {
    private var responses: [Result<String, ExpiryTestError>]
    private let expectedKey: SigningKeyProxy
    private(set) var calls = 0
    private(set) var usedExpectedKey = true

    init(responses: [Result<String, ExpiryTestError>], expectedKey: SigningKeyProxy) {
        self.responses = responses
        self.expectedKey = expectedKey
    }

    func getWalletAttestation(signingKey: SigningKeyProxy) async throws -> String {
        calls += 1
        if case .secKey(let key) = signingKey, case .secKey(let expected) = expectedKey {
            usedExpectedKey = usedExpectedKey && CFEqual(key, expected)
        } else {
            usedExpectedKey = false
        }
        guard !responses.isEmpty else { throw ExpiryTestError.unavailable }
        let response = responses.removeFirst()
        await Task.yield()
        return try response.get()
    }

    nonisolated func getKeysAttestation(keys: [any JWK], nonce: String?) async throws -> String {
        throw ExpiryTestError.unavailable
    }
}
