import Foundation
import Testing
@preconcurrency import JOSESwift
import MdocDataModel18013
import MdocSecurity18013
import OpenID4VCI
import WalletStorage
@testable import EudiWalletKit

@Suite("Plain JWT fallback after key attestation failure")
struct PlainJwtProofFallbackTests {
    private enum Failure: Error, Equatable { case unavailable, requestFailed }

    private actor Provider: WalletAttestationsProvider {
        let cancellation: Bool
        let succeeds: Bool
        let urlCancellation: Bool
        var requestedNonces: [String?] = []
        var thumbprints: [String] = []

        init(cancellation: Bool = false, succeeds: Bool = false, urlCancellation: Bool = false) {
            self.cancellation = cancellation
            self.succeeds = succeeds
            self.urlCancellation = urlCancellation
        }

        func getWalletAttestation(signingKey: SigningKeyProxy) async throws -> String {
            throw Failure.unavailable
        }

        private func record(nonce: String?, thumbprints: [String]) {
            requestedNonces.append(nonce)
            self.thumbprints = thumbprints
        }

        nonisolated func getKeysAttestation(keys: [any JWK], nonce: String?) async throws -> String {
            await record(nonce: nonce, thumbprints: try keys.map { try $0.thumbprint(algorithm: .SHA256) })
            if cancellation { throw CancellationError() }
            if urlCancellation { throw URLError(.cancelled) }
            if succeeds {
                func base64url(_ data: Data) -> String {
                    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
                }
                let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "key-attestation+jwt"])
                let payload = try JSONSerialization.data(withJSONObject: ["iat": 1, "attested_keys": keys.map(\.parameters)])
                // Parsing is exercised here; issuer-side signature verification is outside this test.
                return [base64url(header), base64url(payload), base64url(Data(repeating: 0, count: 64))].joined(separator: ".")
            }
            throw Failure.unavailable
        }
    }

    private func makeKeys(provider: Provider, allowPlainJwt: Bool = true,
                          supportsPlainJwt: Bool = true, requiresJwtAttestation: Bool = false,
                          formatIdentifier: String? = nil, attestationAlgorithms: [String] = ["ES256"],
                          jwtAlgorithms: [String] = ["ES256"], preferredCurve: CoseEcCurve = .P256) async throws -> [BindingKey] {
        SecureAreaRegistry.shared.register(secureArea: KeyAttestationTestSecureArea.shared)
        let storageService = TestDataStorageService()
        #if canImport(EudiEtsi1196x2)
        let trust = TrustConfiguration(trustSource: ReferenceTrustTestFixtures.trustSource)
        #else
        let trust = TrustConfiguration(rootIaca: [])
        #endif
        let service = try OpenId4VciService(
            uiCulture: nil,
            config: OpenId4VciConfiguration(
                credentialIssuerURL: "https://issuer.example.com",
                keyAttestationsConfig: KeyAttestationConfiguration(walletAttestationsProvider: provider),
                allowPlainJwtProof: allowPlainJwt),
            networking: TestNetworking(metadata: Data()),
            storage: StorageManager(storageService: storageService), storageService: storageService,
            trustConfig: trust, localAuthenticationContext: ThreadSafeAuthContext())
        var configuration = CredentialConfiguration(
            configurationIdentifier: try CredentialConfigurationIdentifier(value: "test"),
            credentialIssuerIdentifier: "https://issuer.example.com",
            supportsAttestationProofType: true,
            supportsJwtProofTypeWithAttestation: requiresJwtAttestation,
            supportsPlainJwtProof: supportsPlainJwt,
            credentialSigningAlgValuesSupported: ["ES256"],
            jwtProofSigningAlgValuesSupported: jwtAlgorithms,
            dpopSigningAlgValuesSupported: nil, clientAttestationPopSigningAlgValuesSupported: nil,
            issuerDisplay: [], display: [], claims: [], format: .sdjwt,
            defaultCredentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 2))
        if let formatIdentifier {
            let data = try #require(Data(name: "pid-demo-openid-credential-issuer", ext: "json", from: Bundle.module))
            var json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
            var credentials = try #require(json["credential_configurations_supported"] as? [String: [String: Any]])
            credentials[formatIdentifier]?["proof_types_supported"] = [
                "attestation": ["proof_signing_alg_values_supported": attestationAlgorithms, "key_attestations_required": [:]] as [String: Any],
                "jwt": ["proof_signing_alg_values_supported": jwtAlgorithms]
            ]
            json["credential_configurations_supported"] = credentials
            let metadata = try JSONDecoder().decode(CredentialIssuerMetadata.self, from: JSONSerialization.data(withJSONObject: json))
            configuration = try await service.getCredentialConfiguration(
                credentialIssuerIdentifier: metadata.credentialIssuerIdentifier.url.absoluteString,
                issuerDisplay: metadata.display, credentialsSupported: metadata.credentialsSupported,
                identifier: formatIdentifier, docType: nil, vct: nil, batchCredentialIssuance: nil,
                dpopSigningAlgValuesSupported: nil, clientAttestationPopSigningAlgValuesSupported: nil)
            #expect(configuration.jwtProofSigningAlgValuesSupported == jwtAlgorithms)
            #expect(configuration.credentialSigningAlgValuesSupported == attestationAlgorithms)
        }
        return try await service.preparePlainJwtFallbackTest(configuration, preferredCurve: preferredCurve)
    }

    @Test("Disjoint proof algorithms prevent fallback in both credential formats", arguments: ["pid-mso-mdoc", "pid-sd-jwt"])
    func disjointAlgorithms(identifier: String) async throws {
        let keys = try await makeKeys(provider: Provider(), formatIdentifier: identifier, jwtAlgorithms: ["ES384"])
        await expectProviderFailure(keys)
    }

    @Test("Shared proof algorithms allow same-key fallback in both formats", arguments: ["pid-mso-mdoc", "pid-sd-jwt"])
    func sharedAlgorithms(identifier: String) async throws {
        let provider = Provider()
        let keys = try await makeKeys(provider: provider, formatIdentifier: identifier,
                                      attestationAlgorithms: ["ES384", "ES256"], jwtAlgorithms: ["ES256"], preferredCurve: .P384)
        let fallback = try await OpenId4VciService.withPlainJwtProofFallback(bindingKeys: keys) { keys in
            if case let .attestation(attest) = keys.first { _ = try await attest("nonce") }
            return keys
        }
        let thumbprints = try fallback.map { key -> String in
            guard case let .jwt(_, jwk, _, _) = key else { throw Failure.requestFailed }
            #expect(jwk.parameters["alg"] == "ES256")
            return try jwk.thumbprint(algorithm: .SHA256)
        }
        #expect(thumbprints == (await provider.thumbprints))
    }

    @Test("A failed attestation retries with every original credential key")
    func fallbackPreservesKeys() async throws {
        let provider = Provider()
        let keys = try await makeKeys(provider: provider)
        #expect(await provider.requestedNonces.isEmpty) // No eager, nonce-less attestation.
        let usedKeys = try await OpenId4VciService.withPlainJwtProofFallback(bindingKeys: keys) { keys in
            if case let .attestation(attest) = keys.first {
                _ = try await attest("issuer-nonce")
            }
            return keys
        }
        #expect(usedKeys.count == 2)
        let thumbprints = try usedKeys.map { key -> String in
            guard case let .jwt(_, jwk, _, _) = key else {
                throw Failure.requestFailed
            }
            return try jwk.thumbprint(algorithm: .SHA256)
        }
        #expect(thumbprints == (await provider.thumbprints))
        #expect(await provider.requestedNonces == ["issuer-nonce"])
    }

    @Test("A successful attestation remains the preferred proof")
    func successfulAttestation() async throws {
        let provider = Provider(succeeds: true)
        let keys = try await makeKeys(provider: provider)
        let usedKeys = try await OpenId4VciService.withPlainJwtProofFallback(bindingKeys: keys) { keys in
            if case let .attestation(attest) = keys.first {
                let jwt = try await attest("nonce")
                #expect(jwt.attestedKeys.count == 2)
            }
            return keys
        }
        #expect(usedKeys.count == 1)
        guard case .attestation = usedKeys.first else {
            Issue.record("Successful attestation unexpectedly fell back")
            return
        }
        #expect(await provider.requestedNonces == ["nonce"])
    }

    @Test("A failed plain JWT retry propagates its error")
    func fallbackRequestFails() async throws {
        let provider = Provider()
        let keys = try await makeKeys(provider: provider)
        await #expect(throws: Failure.requestFailed) {
            try await OpenId4VciService.withPlainJwtProofFallback(bindingKeys: keys) { keys in
                if case let .attestation(attest) = keys.first { _ = try await attest("nonce") }
                throw Failure.requestFailed
            }
        }
        #expect(await provider.requestedNonces == ["nonce"])
    }

    @Test("HAIP policy does not fall back")
    func plainJwtDisabled() async throws {
        let keys = try await makeKeys(provider: Provider(), allowPlainJwt: false)
        await expectProviderFailure(keys)
    }

    @Test("Attestation-only metadata does not fall back")
    func plainJwtNotOffered() async throws {
        let keys = try await makeKeys(provider: Provider(), supportsPlainJwt: false)
        await expectProviderFailure(keys)
    }

    @Test("JWT key attestation requirements prevent fallback")
    func jwtRequiresAttestation() async throws {
        let keys = try await makeKeys(provider: Provider(), requiresJwtAttestation: true)
        await expectProviderFailure(keys)
    }

    private func expectProviderFailure(_ keys: [BindingKey]) async {
        await #expect(throws: Failure.unavailable) {
            try await OpenId4VciService.withPlainJwtProofFallback(bindingKeys: keys) { keys in
                if case let .attestation(attest) = keys.first { _ = try await attest("nonce") }
            }
        }
    }

    @Test("Cancellation propagates without a plain JWT retry")
    func cancellation() async throws {
        let keys = try await makeKeys(provider: Provider(cancellation: true))
        await #expect(throws: CancellationError.self) {
            try await OpenId4VciService.withPlainJwtProofFallback(bindingKeys: keys) { keys in
                if case let .attestation(attest) = keys.first { _ = try await attest("nonce") }
            }
        }
    }

    @Test("A cancelled provider network request does not trigger fallback")
    func networkCancellation() async throws {
        let keys = try await makeKeys(provider: Provider(urlCancellation: true))
        await #expect(throws: URLError(.cancelled)) {
            try await OpenId4VciService.withPlainJwtProofFallback(bindingKeys: keys) { keys in
                if case let .attestation(attest) = keys.first { _ = try await attest("nonce") }
            }
        }
    }

    @Test("Unrelated request failures propagate without requesting attestation")
    func requestFailure() async throws {
        let provider = Provider()
        let keys = try await makeKeys(provider: provider)
        await #expect(throws: Failure.requestFailed) {
            try await OpenId4VciService.withPlainJwtProofFallback(bindingKeys: keys) { _ in
                throw Failure.requestFailed
            }
        }
        #expect(await provider.requestedNonces.isEmpty)
    }
}

private extension OpenId4VciService {
    func preparePlainJwtFallbackTest(_ configuration: CredentialConfiguration, preferredCurve: CoseEcCurve) async throws -> [BindingKey] {
        issueReq = try beginIssueDocument(id: UUID().uuidString,
            credentialOptions: configuration.defaultCredentialOptions,
            keyOptions: KeyOptions(curve: preferredCurve, secureAreaName: KeyAttestationTestSecureArea.name))
        return try await initSecurityKeys(configuration, clientId: "test-client").0
    }
}
