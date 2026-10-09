import Foundation
import Testing
import MdocDataModel18013
import MdocDataTransfer18013
@testable import EudiWalletKit

@Suite("Presentation session flow coverage")
struct PresentationSessionCoverageTests {
    @Test("Reports an unavailable document when QR engagement starts with an empty wallet")
    func qrEngagementWithoutDocuments() async throws {
        let service = SessionPresentationService()
        let session = makeSession(service: service, documents: [:])

        try await session.startQrEngagement()

        #expect(session.status == .error)
        #expect(session.uiError?.code == .noDocumentsAvailable)
        #expect(session.uiError?.localizationKey == "request_data_no_document")
        #expect(service.qrEngagementCalls == 0)
    }

    @Test("Publishes the QR engagement payload when the service succeeds")
    func qrEngagementSuccess() async throws {
        let (id, info) = try mdocDocument()
        let service = SessionPresentationService()
        service.qrEngagement = "mdoc:engagement-payload"
        let session = makeSession(service: service, documents: [id: info])

        try await session.startQrEngagement()

        #expect(session.deviceEngagement == "mdoc:engagement-payload")
        #expect(session.status == .qrEngagementReady)
        #expect(service.qrEngagementCalls == 1)
    }

    @Test("Maps a BLE authorization error from QR engagement into a WalletError")
    func qrEngagementTransferError() async throws {
        let (id, info) = try mdocDocument()
        let service = SessionPresentationService()
        service.qrEngagementError = MdocHelpers.makeError(code: .bleNotAuthorized)
        let session = makeSession(service: service, documents: [id: info])

        try await session.startQrEngagement()

        #expect(session.status == .error)
        #expect(session.uiError?.code == .bleNotAuthorized)
        #expect(session.uiError?.innerError != nil)
    }

    @Test("Decodes a request by document type and exposes reader-authentication information")
    func decodesMdocRequest() async throws {
        let (id, info) = try mdocDocument()
        let service = SessionPresentationService(flow: .ble)
        service.wrpVerifierWarnings = ["query-1": [PresentationPolicyViolation(reason: .other, message: "review verifier")]]
        let session = makeSession(service: service, documents: [id: info])
        var request = userRequest(for: info.docType, issuedInfo: info)
        request.readerAuthResults[""] = ReaderAuthenticationResult(
            isValidated: true,
            certificateIssuer: "Reader CA",
            validationMessage: "validated",
            legalName: "Example Verifier"
        )

        try await MainActor.run { try session.decodeRequest([request]) }

        #expect(session.status == .requestReceived)
        #expect(session.readerCertIssuer == "Reader CA")
        #expect(session.readerCertIssuerValid == true)
        #expect(session.readerCertValidationMessage == "validated")
        #expect(session.readerLegalName == "Example Verifier")
        #expect(session.disclosedDocumentSets.count == 1)
        #expect(session.disclosedDocumentSets[0].docElements.count == 1)
        #expect(session.disclosedDocumentSets[0].docElements[0].isMsoMdoc)
        #expect(session.disclosedDocumentSets[0].warnings?.first?.message == "review verifier")
        #expect(session.wrpVerifierWarnings == service.wrpVerifierWarnings)
    }

    @Test("Uses request names for OpenID4VP warnings and reports unmatched requests")
    func decodesOpenIdRequestAndMissingData() async throws {
        let (id, info) = try mdocDocument()
        let service = SessionPresentationService(flow: .openid4vp(qrCode: Data()))
        service.wrpVerifierWarnings = ["share-request": [PresentationPolicyViolation(reason: .overAskedClaims(docType: info.docType, claims: nil), message: "scope warning")]]
        let session = makeSession(service: service, documents: [id: info])
        var request = userRequest(for: info.docType, issuedInfo: info)
        request.requestName = "share-request"

        try await MainActor.run { try session.decodeRequest([request]) }
        #expect(session.disclosedDocumentSets.first?.warnings?.first?.message == "scope warning")

        var unmatched = userRequest(for: info.docType, issuedInfo: info)
        unmatched.itemsRequested = [:]
        do {
            try await MainActor.run { try session.decodeRequest([unmatched]) }
            Issue.record("Expected a no-documents error when the request has no matching items")
        } catch let error as WalletError {
            #expect(error.code == .noDocumentsAvailable)
            #expect(error.localizationKey == "request_data_no_document")
        }
    }

    @Test("Rejects decoding when no documents are stored")
    func decodeRequestWithoutDocuments() async {
        let session = makeSession(service: SessionPresentationService(), documents: [:])
        do {
            try await MainActor.run { try session.decodeRequest([]) }
            Issue.record("Expected a no-documents error")
        } catch let error as WalletError {
            #expect(error.code == .noDocumentsAvailable)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("Marks a response sent and then disconnected after a successful round trip")
    func sendsResponseAndWaitsForDisconnect() async throws {
        let service = SessionPresentationService()
        let session = makeSession(service: service, documents: [:])

        try await session.sendResponse(userAccepted: true, itemsToSend: [:])
        #expect(service.responseCalls == 1)
        #expect(session.status == .responseSent)
        #expect(service.transactionLog.transactionResult == .completed)

        await session.waitForDisconnect()
        #expect(service.disconnectCalls == 1)
        #expect(session.status == .disconnected)
    }

    @Test("Returns early when disconnect is requested before a response was sent")
    func ignoresPrematureDisconnectWait() async {
        let service = SessionPresentationService()
        let session = makeSession(service: service, documents: [:])

        await session.waitForDisconnect()

        #expect(service.disconnectCalls == 0)
        #expect(session.status == .initializing)
    }

    @Test("Reports a disconnect failure in the session error state")
    func disconnectFailure() async {
        let service = SessionPresentationService()
        service.disconnectError = NSError(domain: "transport", code: 4, userInfo: [NSLocalizedDescriptionKey: "lost connection"])
        let session = makeSession(service: service, documents: [:])
        session.status = .responseSent

        await session.waitForDisconnect()

        #expect(service.disconnectCalls == 1)
        #expect(session.status == .error)
        #expect(session.uiError?.description == "lost connection")
    }

    private func userRequest(for docType: String, issuedInfo: DocPresentInfo) -> UserRequestInfo {
        let issuerSigned = try! issuerSigned(from: issuedInfo)
        let namespace = issuerSigned.issuerNameSpaces!.nameSpaces.first!.key
        let element = issuerSigned.issuerNameSpaces![namespace]!.first!.elementIdentifier
        return UserRequestInfo(
            docDataFormats: [docType: .cbor],
            itemsRequested: [docType: [namespace: [RequestItem(elementPath: [element])]]],
            requestName: "consent"
        )
    }

    private func makeSession(service: SessionPresentationService, documents: [String: DocPresentInfo]) -> PresentationSession {
        PresentationSession(
            presentationService: service,
            docIdToPresentInfo: documents,
            documentKeyIndexes: [:],
            userAuthenticationRequired: false,
            localAuthenticationContext: ThreadSafeAuthContext()
        )
    }

    private func mdocDocument() throws -> (String, DocPresentInfo) {
        let fixture = try #require(Data(name: "mdoc-mdl", ext: "txt", from: Bundle.module))
        let text = try #require(String(data: fixture, encoding: .utf8)).trimmingCharacters(in: .whitespacesAndNewlines)
        let data = try #require(Data(base64urlEncoded: text))
        let issuerSigned = try IssuerSigned(data: [UInt8](data))
        let docType = issuerSigned.issuerAuth.mso.docType
        return ("doc-id", DocPresentInfo(
            docType: docType,
            secureAreaName: nil,
            docDataFormat: .cbor,
            displayName: "Driver License",
            docClaims: [],
            typedData: .msoMdoc(issuerSigned)
        ))
    }

    private func issuerSigned(from info: DocPresentInfo) throws -> IssuerSigned {
        guard case .msoMdoc(let issuerSigned) = info.typedData else {
            throw WalletError(description: "Expected an mdoc test fixture", code: .internalError)
        }
        return issuerSigned
    }
}

private final class SessionPresentationService: @unchecked Sendable, PresentationService {
    var flow: FlowType
    var transactionLog: TransactionEntry = TransactionLogUtils.createEmptyPresentationLog()
    var transactionLogger: (any TransactionLogger)?
    var zkpDocumentIds: [String]?
    var wrpVerifierPolicy: WrpRegistrationPolicy?
    var wrpVerifierWarnings: [String: [PresentationPolicyViolation]]?
    var qrEngagement = ""
    var qrEngagementError: Error?
    var qrEngagementCalls = 0
    var responseCalls = 0
    var disconnectCalls = 0
    var disconnectError: Error?

    init(flow: FlowType = .other) {
        self.flow = flow
    }

    func startQrEngagement(secureAreaName: String?, keyOptions: KeyOptions) async throws -> String {
        qrEngagementCalls += 1
        if let qrEngagementError { throw qrEngagementError }
        return qrEngagement
    }

    func receiveRequest() async throws -> [UserRequestInfo] { [] }

    func sendResponse(
        userAccepted: Bool,
        itemsToSend: RequestItems,
        deviceNameSpacesToSend: RequestDeviceNameSpaces?,
        authenticationContext: ThreadSafeAuthContext,
        onSuccess: (@Sendable (URL?) -> Void)?
    ) async throws {
        responseCalls += 1
        TransactionLogUtils.withResult(.completed, transactionLog: &transactionLog)
        onSuccess?(nil)
    }

    func waitForDisconnect() async throws {
        disconnectCalls += 1
        if let disconnectError { throw disconnectError }
    }
}
