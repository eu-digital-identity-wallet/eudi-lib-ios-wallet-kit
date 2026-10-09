import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import MdocSecurity18013
import Testing
@testable import EudiWalletKit
@testable import OpenID4VP

@Suite("OpenID4VP response selection coverage")
struct OpenId4VpResponseCoverageTests {
    @Test("Builds negative consent responses using requested and preferred direct-post modes")
    func buildsDirectPostResponses() async throws {
        let service = try await makeService()
        let responseURL = try #require(URL(string: "https://verifier.example/response"))
        let requested = try resolvedRequest(responseMode: .directPost(responseURI: responseURL))

        let defaultResponse = try service.buildAuthorizationResponse(resolved: requested, consent: .negative(message: "access_denied"))
        guard case .directPost(let defaultURL, _) = defaultResponse else {
            Issue.record("Expected a direct-post response")
            return
        }
        #expect(defaultURL == responseURL)

        service.openID4VpConfig = OpenId4VpConfiguration(
            clientIdSchemes: [.redirectUri],
            preferredResponseMode: .directPost
        )
        let preferred = try resolvedRequest(responseMode: .query(responseURI: responseURL))
        let preferredResponse = try service.buildAuthorizationResponse(resolved: preferred, consent: .negative(message: "access_denied"))
        guard case .directPost(let preferredURL, _) = preferredResponse else {
            Issue.record("The wallet's preferred response mode should be applied")
            return
        }
        #expect(preferredURL == responseURL)
    }

    @Test("Reports missing response URIs and encryption specifications")
    func reportsMissingResponseDetails() async throws {
        let service = try await makeService()
        service.openID4VpConfig = OpenId4VpConfiguration(
            clientIdSchemes: [.redirectUri],
            preferredResponseMode: .directPost
        )
        do {
            _ = try service.buildAuthorizationResponse(
                resolved: try resolvedRequest(responseMode: nil),
                consent: .negative(message: "access_denied")
            )
            Issue.record("Preferred negative responses require a response URI")
        } catch let error as WalletError {
            #expect(error.code == .internalError)
        }

        service.openID4VpConfig = OpenId4VpConfiguration(clientIdSchemes: [.redirectUri])
        do {
            _ = try service.buildAuthorizationResponse(
                resolved: try resolvedRequest(responseMode: .directPostJWT(responseURI: URL(string: "https://verifier.example/response")!)),
                consent: .negative(message: "access_denied")
            )
            Issue.record("Direct-post JWT responses require verifier encryption metadata")
        } catch let error as WalletError {
            #expect(error.code == .responseEncryptionMissing)
        }
    }

    private func resolvedRequest(responseMode: ResponseMode?) throws -> ResolvedRequestData {
        let dcqlData = try #require(Data(name: "dcql-document-number", ext: "json", from: Bundle.module))
        let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
        let request = ResolvedRequestData.VpTokenData(
            presentationQuery: .byDigitalCredentialsQuery(dcql),
            clientMetaData: nil,
            client: .redirectUri(clientId: "https://verifier.example"),
            nonce: "coverage-nonce",
            responseMode: responseMode,
            state: nil,
            vpFormatsSupported: try VpFormatsSupported.default(),
            responseEncryptionSpecification: nil
        )
        return ResolvedRequestData(request: request)
    }

    private func makeService() async throws -> OpenId4VpService {
        let trustConfig: TrustConfiguration
        #if canImport(EudiEtsi1196x2)
        trustConfig = TrustConfiguration(trustSource: .etsi(.eudiRef), defaultPolicy: .warning)
        #else
        trustConfig = TrustConfiguration(rootIaca: [], defaultPolicy: .warning)
        #endif
        let parameters = InitializeTransferData(
            dataFormats: [:],
            documentData: [:],
            documentKeyIndexes: [:],
            docMetadata: [:],
            docDisplayNames: [:],
            docKeyInfos: [:],
            trustValidator: trustConfig.accessTrustManager,
            deviceAuthMethod: "deviceMac",
            idsToDocTypes: [:],
            hashingAlgs: [:],
            bleTransferMode: .client
        )
        return try await OpenId4VpService(
            parameters: parameters,
            qrCode: Data("openid4vp://request".utf8),
            openID4VpConfig: OpenId4VpConfiguration(clientIdSchemes: [.redirectUri]),
            networking: URLSession.shared,
            trustConfig: trustConfig,
            wrpRegistrationValidator: WrpVpRegistrationValidator(trustConfig: trustConfig)
        )
    }
}
