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
import OpenID4VCI

/// Shares a WIA across exchanges until its expiry, retaining the attested signing key.
actor WalletAttestationCache {
    private struct Entry: Sendable {
        let jwt: ClientAttestationJWT
        let expiresAt: Date

        init(_ value: String) throws {
            let jwt = ClientAttestationJWT(value)
            let claims = try jwt.decodeClaimsSet(LifetimeClaims.self)
            guard claims.exp.isFinite else {
                throw WalletError(description: "Wallet attestation has an invalid expiry", code: .internalError)
            }
            self.jwt = jwt
            self.expiresAt = Date(timeIntervalSince1970: claims.exp)
        }
    }

    private struct LifetimeClaims: Decodable {
        let exp: Double
    }

    private let provider: any WalletAttestationsProvider
    private let signingKey: SigningKeyProxy
    private let clock: any ClockType
    private var cached: Entry?
    private var refreshTask: Task<Entry, Error>?

    init(provider: any WalletAttestationsProvider, signingKey: SigningKeyProxy, clock: any ClockType = Clock()) {
        self.provider = provider
        self.signingKey = signingKey
        self.clock = clock
    }

    func attestation() async throws -> ClientAttestationJWT {
        if let cached, cached.expiresAt > clock.now() {
            return cached.jwt
        }
        if let refreshTask {
            return try await refreshTask.value.jwt
        }

        // Coalesce refreshes across actor reentrancy while the provider request awaits.
        let provider = provider
        let signingKey = signingKey
        let clock = clock
        let task = Task { @concurrent in
            let value = try await provider.getWalletAttestation(signingKey: signingKey)
            let entry = try Entry(value)
            guard entry.expiresAt > clock.now() else {
                throw WalletError(description: "Wallet provider returned an expired attestation", code: .internalError)
            }
            return entry
        }
        refreshTask = task
        defer { refreshTask = nil }
        let entry = try await task.value
        cached = entry
        return entry.jwt
    }
}
