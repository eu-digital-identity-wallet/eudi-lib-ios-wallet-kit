import Foundation
import CryptoKit
import Testing
import OpenID4VP
import MdocDataModel18013
import MdocDataTransfer18013
import protocol OpenID4VP.Networking
import SwiftyJSON
@testable import EudiWalletKit

@Suite("QES transaction data")
struct TransactionDataTests {
    private func approval(ids: [String] = ["pid"], oid: String = "2.16.840.1.101.3.4.2.1") -> [String: Any] {
        ["type": QesApprovalRequest.typeIdentifier, "credential_ids": ids,
         "signatureQualifier": "eu_eidas_qes", "numSignatures": 1,
         "documentDigests": [["label": "Contract", "hash": "YWJj"]], "hashAlgorithmOID": oid]
    }

    private func parse(_ object: [String: Any]) throws -> PresentationTransactionData {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return try .init(encodedValue: data.base64URLEncodedString())
    }

    @Test func typedApprovalAndDefaults() throws {
        let transaction = try parse(approval())
        guard case .qesApprovalRequest(let request) = transaction.payload else { Issue.record("Expected QES approval"); return }
        #expect(request.documentDigests.first?.label == "Contract")
        #expect(request.documentDigests.first?.hashType == "dtbsr")
        #expect(transaction.hashAlgorithms == ["sha-256"])
    }

    @Test(arguments: ["missing", "unknown", "wrongType", "empty", "negative", "badDigest", "badOID", "badAccess", "badQualifier"])
    func malformedApproval(reason: String) throws {
        var object = approval()
        switch reason {
        case "missing": object.removeValue(forKey: "documentDigests")
        case "unknown": object["unknown"] = true
        case "wrongType": object["numSignatures"] = "1"
        case "empty": object["documentDigests"] = []
        case "negative": object["numSignatures"] = -1
        case "badDigest": object["documentDigests"] = [["hash": "abc", "unexpected": true]]
        case "badOID": object["hashAlgorithmOID"] = "unknown"
        case "badAccess": object["documentDigests"] = [["hash": "abc", "access": ["type": "OTP"]]]
        case "badQualifier": object.removeValue(forKey: "signatureQualifier")
        default: break
        }
        #expect(throws: (any Error).self) { try parse(object) }
        do { _ = try parse(object) } catch let error as WalletError { #expect(error.code == .invalidTransactionData) }
    }

    @Test func qesRequestInlineAndReference() throws {
        let object: [String: Any] = ["type": QesRequest.typeIdentifier, "credential_ids": ["pid"], "signatureRequests": [
            ["signatureQualifier": "eu_eidas_qes", "document": "YWJj", "signAlgo": "1.2.840.10045.4.3.2", "signature_format": "P"],
            ["signatureQualifier": "eu_eidas_qes", "href": "https://example.org/document", "signAlgo": "1.2.840.10045.4.3.2"]
        ]]
        guard case .qesRequest(let request) = try parse(object).payload else { Issue.record("Expected QES request"); return }
        #expect(request.signatureRequests.count == 2)
        var invalid = object
        invalid["signatureRequests"] = [["signatureQualifier": "eu_eidas_qes", "document": "abc", "href": "https://example.org", "signAlgo": "1.2"]]
        #expect(throws: (any Error).self) { try parse(invalid) }
    }

    @Test func hashOriginalStringAndCSCApproval() throws {
        let transaction = try parse(approval(oid: "2.16.840.1.101.3.4.2.2"))
        let claims = try PresentationTransactionData.keyBindingClaims([transaction], supportedTypes: [.qesApprovalRequest])
        #expect(claims["transaction_data_hashes_alg"] as? String == "sha-256")
        #expect(claims["transaction_data_hashes"] as? [String] == [Data(SHA256.hash(data: Data(transaction.encodedValue.utf8))).base64URLEncodedString()])
        #expect(claims["org.cloudsignatureconsortium.dm.1.qesApproval"] as? String == Data(SHA384.hash(data: Data(transaction.encodedValue.utf8))).base64EncodedString())
        #expect(claims["transaction_data_hashes"] as? [String] != [Data(SHA256.hash(data: transaction.jsonData)).base64URLEncodedString()])
        #expect(try PresentationTransactionData.keyBindingClaims([], supportedTypes: []).isEmpty)
    }

    @Test func negotiatesHashAlgorithm() throws {
        var object = approval()
        object["transaction_data_hashes_alg"] = ["sha-512"]
        let transaction = try parse(object)
        #expect(throws: (any Error).self) { try PresentationTransactionData.keyBindingClaims([transaction], supportedTypes: [.qesApprovalRequest]) }
        let supported = try SupportedTransactionDataType(type: .init(value: QesApprovalRequest.typeIdentifier), hashAlgorithms: [.sha256, .init(name: "sha-512")])
        let claims = try PresentationTransactionData.keyBindingClaims([transaction], supportedTypes: [supported])
        #expect(claims["transaction_data_hashes_alg"] as? String == "sha-512")
    }

    @Test func rejectsMultipleApprovalsInOneProof() throws {
        let first = try parse(approval())
        #expect(throws: (any Error).self) { try PresentationTransactionData.keyBindingClaims([first, first], supportedTypes: [.qesApprovalRequest]) }
    }

    @Test func assignsOnceAndTriesLaterCredentialIds() throws {
        let transaction = try parse(approval(ids: ["unavailable", "pid", "other"]))
        let selections: CredentialSelectionSet = [
            try .init(credentialId: "doc2", docType: "pid", queryId: .init(value: "other"), optionId: "option", claimQueries: []),
            try .init(credentialId: "doc1", docType: "pid", queryId: .init(value: "pid"), optionId: "option", claimQueries: [])
        ]
        let assignments = try TransactionDataProcessor.assign([transaction], selections: selections, eligibleDocumentIds: ["doc1", "doc2"], supportedTypes: [.qesApprovalRequest])
        #expect(assignments.count == 1)
        #expect(assignments.first?.documentId == "doc1")
        #expect(assignments.first?.queryId == "pid")
        let fallback = try TransactionDataProcessor.assign([transaction], selections: selections, eligibleDocumentIds: ["doc2"], supportedTypes: [.qesApprovalRequest])
        #expect(fallback.first?.documentId == "doc2")
        #expect(throws: (any Error).self) { try TransactionDataProcessor.assign([transaction], selections: selections, eligibleDocumentIds: [], supportedTypes: [.qesApprovalRequest]) }
    }

    @Test func differentQueriesGetDifferentProofsEvenForOneDocument() throws {
        let first = try parse(approval(ids: ["pid"]))
        let second = try parse(approval(ids: ["other"]))
        let selections: CredentialSelectionSet = [try .init(credentialId: "doc", docType: "pid", queryId: .init(value: "pid"),
            optionId: "option", claimQueries: [], queryIds: [.init(value: "pid"), .init(value: "other")])]
        let assigned = try TransactionDataProcessor.assign([first, second], selections: selections, eligibleDocumentIds: ["doc"], supportedTypes: [.qesApprovalRequest])
        #expect(assigned.map(\.queryId) == ["pid", "other"])
        for query in ["pid", "other"] {
            let transactions = assigned.filter { $0.queryId == query }.map(\.transaction)
            let claims = try PresentationTransactionData.keyBindingClaims(transactions, supportedTypes: [.qesApprovalRequest])
            #expect((claims["transaction_data_hashes"] as? [String])?.count == 1)
        }
    }

    @Test func logPayloadsFallBackToRawJSON() throws {
        let transaction = try parse(approval())
        let object = try JSON(data: transaction.jsonData)
        let data = try TransactionalData(content: [object])
        guard case .qesApprovalRequest = data.payloads(supportedTypes: [.qesApprovalRequest]).first else { Issue.record("Expected typed approval"); return }
        guard case .raw(let raw) = data.payloads(supportedTypes: []).first else { Issue.record("Expected raw fallback"); return }
        #expect(raw == object)
        var outdated = object
        outdated["newField"] = true
        let oldLog = try TransactionalData(content: [outdated])
        guard case .raw = oldLog.payloads(supportedTypes: [.qesApprovalRequest]).first else { Issue.record("Invalid historic payload should remain readable"); return }
    }

    @Test func logPreservesDataAndDecision() throws {
        let transaction = try parse(approval())
        let data = try TransactionalData(content: [JSON(data: transaction.jsonData)])
        var log = TransactionLogUtils.createEmptyPresentationLog()
        TransactionLogUtils.withRequest([], policy: nil, name: "Verifier", transactionalData: data, transactionLog: &log)
        let id = log.transactionIdentifier
        for result: TransactionResult in [.completed, .notCompleted] {
            TransactionLogUtils.withResult(result, reason: result == .notCompleted ? "access_denied" : nil, transactionLog: &log)
            let decoded = try JSONDecoder().decode(TransactionEntry.self, from: JSONEncoder().encode(log))
            guard case .presentation(let entry) = decoded else { Issue.record("Expected presentation log"); return }
            #expect(entry.transactionIdentifier == id)
            #expect(entry.transactionalData == data)
            #expect(entry.transactionResult == result)
        }
    }

    @Test func protocolErrorCodesRemainDistinct() {
        let examples: [(ValidationError, WalletError.Code)] = [
            (.invalidTransactionData("bad transaction"), .invalidTransactionData),
            (.invalidScope, .invalidScope), (.invalidRequest, .invalidRequest),
            (.invalidClientMetadata, .invalidClient), (.negativeConsent, .accessDenied),
            (.invalidFormat, .vpFormatsNotSupported), (.invalidRequestUriMethod, .invalidRequestUriMethod),
            (.walletUnavailable, .walletUnavailable)
        ]
        for (error, expected) in examples { #expect(OpenId4VpService.walletErrorCode(error) == expected) }
    }
}

@Suite("Transaction data service errors")
struct TransactionDataServiceTests {
    @Test(arguments: [false, true])
    func reportsMissingOrMalformedTransactionToVerifier(malformed: Bool) async throws {
        var object: [String: Any] = ["type": QesApprovalRequest.typeIdentifier, "credential_ids": ["pid"],
            "signatureQualifier": "eu_eidas_qes", "numSignatures": 1,
            "documentDigests": [["hash": "YWJj"]], "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"]
        if malformed { object["unknown"] = true }
        let transaction = try JSONSerialization.data(withJSONObject: object).base64URLEncodedString()
        var url = URLComponents(string: "openid4vp://authorize")!
        url.queryItems = [
            .init(name: "client_id", value: "redirect_uri:https://example.org/response"),
            .init(name: "response_uri", value: "https://example.org/response"),
            .init(name: "response_type", value: "vp_token"), .init(name: "response_mode", value: "direct_post"),
            .init(name: "nonce", value: "nonce"),
            .init(name: "dcql_query", value: #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["pid"]}}]}"#),
            .init(name: "transaction_data", value: String(decoding: try JSONEncoder().encode([transaction]), as: UTF8.self))
        ]
        #if canImport(EudiEtsi1196x2)
        let trust = TrustConfiguration(trustSource: .etsi(.eudiRef))
        #else
        let trust = TrustConfiguration(rootIaca: [])
        #endif
        let parameters = InitializeTransferData(dataFormats: [:], documentData: [:], documentKeyIndexes: [:],
            docMetadata: [:], docDisplayNames: [:], docKeyInfos: [:], trustValidator: trust.accessTrustManager,
            deviceAuthMethod: "deviceSignature", idsToDocTypes: [:], hashingAlgs: [:], bleTransferMode: .server)
        let network = TransactionServiceNetwork()
        let service = try await OpenId4VpService(parameters: parameters, qrCode: Data(url.string!.utf8),
            openID4VpConfig: .init(supportedTransactionDataTypes: [.qesApprovalRequest], validateRegistrationCertificate: false),
            networking: network, trustConfig: trust, wrpRegistrationValidator: .init(trustConfig: trust))
        let session = PresentationSession(presentationService: service, docIdToPresentInfo: [:], documentKeyIndexes: [:],
            userAuthenticationRequired: false, localAuthenticationContext: ThreadSafeAuthContext())
        let result = await session.receiveRequest()
        #expect(result == nil)
        let code = await MainActor.run { session.uiError?.code }
        #expect(code == .invalidTransactionData)
        let bodies = await network.bodies
        #expect(bodies.count == 1)
        #expect(bodies.first?.contains("error=invalid_transaction_data") == true)
        #expect(bodies.first?.contains("vp_token=") == false)
        guard case .presentation(let log) = service.transactionLog else { Issue.record("Expected presentation"); return }
        #expect(log.transactionResult == .notCompleted)
        #expect(log.transactionalData?.content.count == 1)
        #expect(log.transactionalData?.content.first?["type"].string == QesApprovalRequest.typeIdentifier)
    }
}

private actor TransactionServiceNetwork: Networking {
    var bodies: [String] = []
    func data(from url: URL) async throws -> (Data, URLResponse) { throw URLError(.unsupportedURL) }
    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        bodies.append(String(decoding: request.httpBody ?? Data(), as: UTF8.self))
        return (Data("{}".utf8), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
    }
}
