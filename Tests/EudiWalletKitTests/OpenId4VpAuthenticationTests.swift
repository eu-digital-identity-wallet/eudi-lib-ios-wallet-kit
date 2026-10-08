import CryptoKit
import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import MdocSecurity18013
import OpenID4VP
import protocol OpenID4VP.Networking
import SwiftASN1
import Testing
import X509
@testable import EudiWalletKit

@Suite("OpenID4VP request authentication")
struct OpenId4VpAuthenticationTests {
    private static let responseURI = "https://verifier.example/response"
    private static let requestURI = "https://verifier.example/request"
    private static let docType = "org.iso.18013.5.1.mDL"

    @Test("Unsupported client IDs cannot bypass JAR authentication", arguments: [false, true])
    func rejectsFallbackIdentity(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        // URL-valued IDs let the old redirect fallback reach its no-op signature check.
        for clientId in ["verifier.example", Self.responseURI,
                         "openid_federation:\(Self.responseURI)", "verifier_attestation:\(Self.responseURI)"] {
            let token = try fixture.token(clientId: clientId, validSignature: false)
            for registration in [RegistrationMode.disabled, .warning, .enforce] {
                let (service, network) = try await makeService(clientId: clientId, token: token,
                    byReference: byReference, anchors: [fixture.der], registration: registration)
                await assertRejected(service, network: network)
                #expect(service.readerCertificateIssuer == nil)
                #expect(service.certificateChain == nil)
            }
        }
    }

    @Test("An accepted certificate cannot compensate for an invalid JAR signature", arguments: [false, true])
    func rejectsInvalidSignature(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: false)
            let (service, network) = try await makeService(clientId: clientId, token: token,
                byReference: byReference, anchors: [fixture.der])
            await assertRejected(service, network: network)
            // The trust callback succeeded; rejection must still happen before consent.
            #expect(service.readerAuthValidated)
        }
    }

    @Test("A signed request with an untrusted certificate cannot reach consent")
    func rejectsUntrustedCertificate() async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: true)
            let (service, network) = try await makeService(clientId: clientId, token: token, anchors: [])
            await assertRejected(service, network: network)
            #expect(!service.readerAuthValidated)
        }
    }

    @Test("Authenticated X.509 requests reach consent with the expected client ID", arguments: [false, true])
    func acceptsSignedRequest(byReference: Bool) async throws {
        let fixture = try CertificateFixture()
        for clientId in fixture.clientIds {
            let token = try fixture.token(clientId: clientId, validSignature: true)
            let (service, _) = try await makeService(clientId: clientId, token: token,
                byReference: byReference, anchors: [fixture.der])
            let requests = try await service.receiveRequest()
            #expect(!requests.isEmpty)
            #expect(service.resolvedRequestData?.client.id.clientId == clientId)
            let authentication = try #require(requests.first?.readerAuthResults[""])
            #expect(authentication.isValidated)
            #expect(authentication.certificateChain == [fixture.der])
        }
    }

    @Test("Plain redirect-URI requests remain supported without a fabricated legal name")
    func acceptsPlainRedirect() async throws {
        let (service, _) = try await makeService(clientId: "redirect_uri:\(Self.responseURI)", token: nil)
        let requests = try await service.receiveRequest()
        #expect(!requests.isEmpty)
        #expect(service.resolvedRequestData?.legalName == nil)
        #expect(!service.readerAuthValidated)
    }

    private func assertRejected(_ service: OpenId4VpService, network: RequestNetworking) async {
        await #expect(throws: WalletError.self) { try await service.receiveRequest() }
        #expect(service.resolvedRequestData == nil)
        #expect(service.dcql == nil)
        await #expect(throws: WalletError.self) {
            try await service.sendResponse(userAccepted: true, itemsToSend: [:],
                authenticationContext: ThreadSafeAuthContext(), onSuccess: nil)
        }
        #expect(await network.posts == 0)
        #expect(service.presentedDocumentIds.isEmpty)
    }

    private enum RegistrationMode { case disabled, warning, enforce }

    private func makeService(clientId: String, token: String?, byReference: Bool = false,
                             anchors: [Data] = [], registration: RegistrationMode = .disabled) async throws -> (OpenId4VpService, RequestNetworking) {
        let registrationPolicy: TrustPolicy = registration == .warning ? .warning : .enforce
        #if canImport(EudiEtsi1196x2)
        let trust = TrustConfiguration(trustSource: .staticList(.init(rootCertificates: anchors, method: .directTrust)), wrprcVpTrustPolicy: registrationPolicy)
        #else
        let trust = TrustConfiguration(rootIaca: anchors.map { [$0] }, wrprcVpTrustPolicy: registrationPolicy)
        #endif
        let resource = try #require(Bundle.module.url(forResource: "mdoc-mdl", withExtension: "txt"))
        let encoded = try String(contentsOf: resource, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let document = try #require(Data(base64URLEncoded: encoded))
        let parameters = InitializeTransferData(dataFormats: ["mdl": "cbor"], documentData: ["mdl": document],
            documentKeyIndexes: [:], docMetadata: [:], docDisplayNames: [:], docKeyInfos: [:],
            trustValidator: trust.accessTrustManager, deviceAuthMethod: "deviceSignature",
            idsToDocTypes: ["mdl": Self.docType], hashingAlgs: [:], bleTransferMode: .server)
        var url = URLComponents(string: "openid4vp://authorize")!
        if let token {
            url.queryItems = [.init(name: "client_id", value: clientId),
                .init(name: byReference ? "request_uri" : "request", value: byReference ? Self.requestURI : token)]
        } else {
            url.queryItems = try Self.payload(clientId: clientId).map { key, value in
                let text: String
                if let string = value as? String { text = string }
                else { text = String(decoding: try JSONSerialization.data(withJSONObject: value), as: UTF8.self) }
                return URLQueryItem(name: key, value: text)
            }
        }
        let network = RequestNetworking(token: token ?? "")
        let service = try await OpenId4VpService(parameters: parameters, qrCode: Data(url.string!.utf8),
            openID4VpConfig: .init(validateRegistrationCertificate: registration != .disabled), networking: network,
            trustConfig: trust, wrpRegistrationValidator: .init(trustConfig: trust))
        return (service, network)
    }

    private static func payload(clientId: String) -> [String: Any] {
        ["client_id": clientId, "response_type": "vp_token", "response_mode": "direct_post",
         "response_uri": responseURI, "nonce": "authentication-regression-test",
         "dcql_query": ["credentials": [["id": "mdl", "format": "mso_mdoc",
             "meta": ["doctype_value": docType], "claims": [["path": ["org.iso.18013.5.1", "family_name"]]]]]]]
    }

    private struct CertificateFixture {
        let key = P256.Signing.PrivateKey()
        let der: Data
        var clientIds: [String] {
            ["x509_san_dns:verifier.example", "x509_hash:\(Self.base64URL(Data(SHA256.hash(data: der))))"]
        }
        init() throws {
            let name = try DistinguishedName { CommonName("verifier.example"); OrganizationName("Test Verifier") }
            let certificate = try Certificate(version: .v3, serialNumber: .init(bytes: [1]), publicKey: .init(key.publicKey),
                notValidBefore: Date().addingTimeInterval(-3600), notValidAfter: Date().addingTimeInterval(86400),
                issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
                extensions: Certificate.Extensions {
                    Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                    KeyUsage(digitalSignature: true, keyCertSign: true)
                    SubjectAlternativeNames([.dnsName("verifier.example")])
                }, issuerPrivateKey: .init(key))
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            der = Data(serializer.serializedBytes)
        }
        func token(clientId: String, validSignature: Bool) throws -> String {
            let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [der.base64EncodedString()]])
            let payload = try JSONSerialization.data(withJSONObject: OpenId4VpAuthenticationTests.payload(clientId: clientId))
            let input = "\(Self.base64URL(header)).\(Self.base64URL(payload))"
            let signature = validSignature ? try key.signature(for: Data(input.utf8)).rawRepresentation : Data(repeating: 0, count: 64)
            return "\(input).\(Self.base64URL(signature))"
        }
        static func base64URL(_ data: Data) -> String {
            data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
    }

    private actor RequestNetworking: Networking {
        let token: String
        var posts = 0
        init(token: String) { self.token = token }
        func data(from url: URL) async throws -> (Data, URLResponse) {
            #expect(url.absoluteString == OpenId4VpAuthenticationTests.requestURI)
            return (Data(token.utf8), HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!)
        }
        func data(for request: URLRequest) async throws -> (Data, URLResponse) {
            if request.httpMethod == "POST" { posts += 1; throw URLError(.unsupportedURL) }
            return try await data(from: #require(request.url))
        }
    }
}
