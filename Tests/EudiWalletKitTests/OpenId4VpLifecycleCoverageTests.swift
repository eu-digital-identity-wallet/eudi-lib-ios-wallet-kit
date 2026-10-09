import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import MdocSecurity18013
import Testing
@testable import EudiWalletKit

@Suite("OpenID4VP service lifecycle coverage")
struct OpenId4VpLifecycleCoverageTests {
    @Test("Initializes request state, lazily initializes unlock data, and disconnects")
    func serviceLifecycle() async throws {
        let service = try await makeService(qrCode: "openid4vp://request")
        let qrCode = Data("openid4vp://request".utf8)

        #expect(service.flow == .openid4vp(qrCode: qrCode))
        #expect(service.status == .initialized)
        #expect(service.deviceAlgorithm == .es256)
        #expect(OpenId4VpService.filterFormat(.cbor, fmt: .cbor))
        #expect(!OpenId4VpService.filterFormat(.sdjwt, fmt: .cbor))
        #expect(service.getWalletConf() != nil)
        _ = service.decodeDocuments()

        #expect(try await service.startQrEngagement(secureAreaName: nil, keyOptions: KeyOptions(curve: .P256)) == "")
        #expect(try await service.startQrEngagement(secureAreaName: nil, keyOptions: KeyOptions(curve: .P256)) == "")
        try await service.waitForDisconnect()
        #expect(service.status == .disconnected)
    }

    @Test("Rejects an invalid OpenID4VP link before network authorization")
    func rejectsInvalidLink() async throws {
        let service = try await makeService(qrCode: "http://[")
        do {
            _ = try await service.receiveRequest()
            Issue.record("An invalid QR link should fail before authorization")
        } catch let error as WalletError {
            #expect(error.code == .invalidQueryResolution)
        }
    }

    @Test("Rejects a response before receiving a request")
    func rejectsResponseWithoutRequest() async throws {
        let service = try await makeService(qrCode: "openid4vp://request")
        do {
            try await service.sendResponse(
                userAccepted: false,
                itemsToSend: [:],
                authenticationContext: ThreadSafeAuthContext(),
                onSuccess: nil
            )
            Issue.record("A response requires a resolved presentation request")
        } catch let error as WalletError {
            #expect(error.code == .internalError)
        }
    }

    private func makeService(qrCode: String) async throws -> OpenId4VpService {
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
            qrCode: Data(qrCode.utf8),
            openID4VpConfig: OpenId4VpConfiguration(clientIdSchemes: [.redirectUri]),
            networking: URLSession.shared,
            trustConfig: trustConfig,
            wrpRegistrationValidator: WrpVpRegistrationValidator(trustConfig: trustConfig)
        )
    }
}
