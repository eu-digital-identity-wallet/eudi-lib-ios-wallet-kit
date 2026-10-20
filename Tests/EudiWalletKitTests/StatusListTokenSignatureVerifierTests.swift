import CryptoKit
import Foundation
import JSONWebSignature
import MdocSecurity18013
import StatiumSwift
import SwiftASN1
import Testing
import X509
@testable import EudiWalletKit

struct StatusListTokenSignatureVerifierTests {
    private func configuration(_ policy: TrustPolicy, anchors: [Data] = []) -> TrustConfiguration {
        #if canImport(EudiEtsi1196x2)
        TrustConfiguration(trustSource: .staticList(.init(rootCertificates: anchors, method: .directTrust)), statusTrustPolicy: policy)
        #else
        TrustConfiguration(rootIaca: anchors.map { [$0] }, statusTrustPolicy: policy)
        #endif
    }

    private func fixture() throws -> (key: P256.Signing.PrivateKey, certificate: Data) {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName("Status signature test") }
        let now = Date()
        let certificate = try Certificate(
            version: .v3, serialNumber: .init(bytes: [1]), publicKey: .init(key.publicKey),
            notValidBefore: now.addingTimeInterval(-3600), notValidAfter: now.addingTimeInterval(86400),
            issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                KeyUsage(digitalSignature: true, keyCertSign: true)
            },
            issuerPrivateKey: .init(key)
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return (key, Data(serializer.serializedBytes))
    }

    private func token(algorithm: String?, certificates: [String]?, payload: Data = Data("{}".utf8), signature: Data = Data()) throws -> Data {
        var header: [String: Any] = ["typ": "statuslist+jwt"]
        if let algorithm { header["alg"] = algorithm }
        if let certificates { header["x5c"] = certificates }
        let encodedHeader = try JSONSerialization.data(withJSONObject: header, options: .sortedKeys)
        return Data("\(base64URL(encodedHeader)).\(base64URL(payload)).\(base64URL(signature))".utf8)
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    @Test("Unsigned JWTs fail even with an accepted certificate", arguments: [TrustPolicy.enforce, .warning])
    func rejectsNone(policy: TrustPolicy) async throws {
        let fixture = try fixture()
        let token = try token(algorithm: "none", certificates: [fixture.certificate.base64EncodedString()])
        let verifier = StatusListTokenSignatureVerifier(trustConfig: configuration(policy, anchors: [fixture.certificate]))
        await #expect(throws: (any Error).self) {
            try await verifier.verify(statusListToken: token, format: .jwt, at: Date())
        }
    }

    @Test("Missing, symmetric and unsupported algorithms fail under both policies", arguments: [TrustPolicy.enforce, .warning])
    func rejectsAlgorithms(policy: TrustPolicy) async throws {
        let fixture = try fixture()
        for algorithm in [nil, "HS256", "HS384", "HS512", "invalid", "unknown", "NONE"] as [String?] {
            let token = try token(algorithm: algorithm, certificates: [fixture.certificate.base64EncodedString()], signature: Data([1]))
            let verifier = StatusListTokenSignatureVerifier(trustConfig: configuration(policy, anchors: [fixture.certificate]))
            await #expect(throws: (any Error).self) {
                try await verifier.verify(statusListToken: token, format: .jwt, at: Date())
            }
        }
    }

    @Test("Missing and malformed certificates remain fatal", arguments: [TrustPolicy.enforce, .warning])
    func rejectsCertificates(policy: TrustPolicy) async throws {
        for certificates in [nil, [], ["bad certificate"]] as [[String]?] {
            let token = try token(algorithm: "ES256", certificates: certificates, signature: Data([1]))
            let verifier = StatusListTokenSignatureVerifier(trustConfig: configuration(policy))
            await #expect(throws: (any Error).self) {
                try await verifier.verify(statusListToken: token, format: .jwt, at: Date())
            }
        }
    }

    @Test("Signed status lists retain indexed status and chain-warning behavior")
    func signedStatusList() async throws {
        let fixture = try fixture()
        let url = try #require(URL(string: "https://status.example/list"))
        let now = Date()
        // zlib-compressed one-bit list: index 0 valid, index 1 invalid.
        let payload = try JSONSerialization.data(withJSONObject: [
            "sub": url.absoluteString, "iat": floor(now.timeIntervalSince1970),
            "exp": floor(now.timeIntervalSince1970) + 3600,
            "status_list": ["bits": 1, "lst": "eJxjAgAAAwAD"]
        ])
        let unsigned = try token(algorithm: "ES256", certificates: [fixture.certificate.base64EncodedString()], payload: payload)
        let signingInput = Data(unsigned.dropLast())
        let signature = try fixture.key.signature(for: signingInput).rawRepresentation
        let signed = try token(algorithm: "ES256", certificates: [fixture.certificate.base64EncodedString()], payload: payload, signature: signature)
        let trusted = configuration(.enforce, anchors: [fixture.certificate])
        try await StatusListTokenSignatureVerifier(trustConfig: trusted).verify(statusListToken: signed, format: .jwt, at: now)
        let warningVerifier = StatusListTokenSignatureVerifier(trustConfig: configuration(.warning))
        try await warningVerifier.verify(statusListToken: signed, format: .jwt, at: now)
        await #expect(throws: (any Error).self) {
            try await StatusListTokenSignatureVerifier(trustConfig: configuration(.enforce)).verify(statusListToken: signed, format: .jwt, at: now)
        }
        for policy in [TrustPolicy.enforce, .warning] {
            let verifier = StatusListTokenSignatureVerifier(trustConfig: configuration(policy, anchors: [fixture.certificate]))
            let badSignature = try token(algorithm: "ES256", certificates: [fixture.certificate.base64EncodedString()], payload: payload, signature: Data(repeating: 0, count: 64))
            await #expect(throws: (any Error).self) {
                try await verifier.verify(statusListToken: badSignature, format: .jwt, at: now)
            }
            let emptySignature = try token(algorithm: "ES256", certificates: [fixture.certificate.base64EncodedString()], payload: payload)
            await #expect(throws: (any Error).self) {
                try await verifier.verify(statusListToken: emptySignature, format: .jwt, at: now)
            }
        }
        let fetcher = StatusListTokenFetcher(networkingService: StubNetworking(data: signed), verifier: warningVerifier, dateProvider: { now })
        let result = await GetStatus().getStatus(index: 0, url: url, fetchClaims: fetcher.getStatusClaims, clockSkew: 0)
        switch result {
        case .success(let status): #expect(status == .valid)
        case .failure(let error): Issue.record("Valid signed status list failed: \(error)")
        }
        let unsignedToken = try token(algorithm: "none", certificates: [fixture.certificate.base64EncodedString()], payload: payload)
        let unsignedFetcher = StatusListTokenFetcher(networkingService: StubNetworking(data: unsignedToken), verifier: warningVerifier, dateProvider: { now })
        let unsignedResult = await GetStatus().getStatus(index: 0, url: url, fetchClaims: unsignedFetcher.getStatusClaims, clockSkew: 0)
        if case .success = unsignedResult { Issue.record("Unsigned token returned a credential status") }
    }

    private struct StubNetworking: NetworkingServiceType {
        let data: Data
        let session = URLSession(configuration: .ephemeral)
        func get(url: URL, headers: [String: String]) async -> Result<Data, NetworkingError> { .success(data) }
    }
}
