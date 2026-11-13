import Foundation
import CryptoKit
import Testing
import SwiftCBOR
import OpenID4VP
import protocol OpenID4VP.Networking
import MdocDataModel18013
import MdocDataTransfer18013
import MdocSecurity18013
@testable import EudiWalletKit

@Suite("Mdoc transaction data")
struct MdocTransactionDataTests {
    private let namespace = "org.cloudsignatureconsortium.dm.1"

    private func approval(ids: [String] = ["mdoc"], oid: String = "2.16.840.1.101.3.4.2.2") throws -> PresentationTransactionData {
        // Whitespace must survive decoding: mdoc hashes the received JSON bytes, not a reserialization.
        let json = """
        { "type": "\(QesApprovalRequest.typeIdentifier)", "credential_ids": \(String(decoding: try JSONEncoder().encode(ids), as: UTF8.self)),
          "signatureQualifier": "eu_eidas_qes", "numSignatures": 1,
          "documentDigests": [{"hash": "YWJj"}], "hashAlgorithmOID": "\(oid)" }
        """
        return try .init(encodedValue: Data(json.utf8).base64URLEncodedString())
    }

    @Test(arguments: [false, true])
    func mdocHashesDecodedBytesWithSha256(namespaceAuthorization: Bool) throws {
        let transaction = try approval()
        let authorization = namespaceAuthorization ? KeyAuthorizations(nameSpaces: [namespace]) : KeyAuthorizations(dataElements: [namespace: ["qesApproval"]])
        let result = try #require(try MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: authorization, supportedTypes: [.qesApprovalRequest]))
        #expect(result[namespace]?["qesApproval"] == .byteString(Array(SHA256.hash(data: transaction.jsonData))))
        #expect(result[namespace]?["qesApproval"] != .byteString(Array(SHA256.hash(data: Data(transaction.encodedValue.utf8)))))
        // The mdoc binding is fixed to SHA-256, independently of hashAlgorithmOID.
        #expect(result[namespace]?["qesApproval"] != .byteString(Array(SHA384.hash(data: transaction.jsonData))))
    }

    @Test func rejectsMissingAuthorizationAndUnsupportedBindings() throws {
        let transaction = try approval()
        for authorization in [nil, KeyAuthorizations(), KeyAuthorizations(nameSpaces: ["other"]), KeyAuthorizations(dataElements: [namespace: ["other"]])] {
            #expect(throws: (any Error).self) {
                try MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: authorization, supportedTypes: [.qesApprovalRequest])
            }
        }
        let authorized = KeyAuthorizations(nameSpaces: [namespace])
        #expect(throws: (any Error).self) { try MdocTransactionData.deviceNameSpaces([transaction, transaction], keyAuthorizations: authorized, supportedTypes: [.qesApprovalRequest]) }
        #expect(throws: (any Error).self) { try MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: authorized, supportedTypes: []) }
        let custom = try PresentationTransactionData(encodedValue: Data(#"{"type":"custom","credential_ids":["mdoc"]}"#.utf8).base64URLEncodedString())
        #expect(throws: (any Error).self) { try MdocTransactionData.deviceNameSpaces([custom], keyAuthorizations: authorized, supportedTypes: [.init(type: .init(value: "custom"))]) }
    }

    @Test func mergesNamespacesAndRejectsConflictingApproval() throws {
        let transaction = try approval()
        let existing = DeviceNameSpaces(deviceNameSpaces: ["other": .init(deviceSignedItems: ["value": .utf8String("preserved")])])
        let auth = KeyAuthorizations(nameSpaces: [namespace])
        let result = try #require(try MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: auth, supportedTypes: [.qesApprovalRequest], merging: existing))
        #expect(result["other"]?["value"] == .utf8String("preserved"))
        #expect(try MdocTransactionData.deviceNameSpaces([], keyAuthorizations: nil, supportedTypes: [], merging: existing)?.toCBOR(options: CBOROptions()) == existing.toCBOR(options: CBOROptions()))
        _ = try MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: auth, supportedTypes: [.qesApprovalRequest], merging: result)
        let conflict = DeviceNameSpaces(deviceNameSpaces: [namespace: .init(deviceSignedItems: ["qesApproval": .byteString([0])])])
        #expect(throws: (any Error).self) { try MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: auth, supportedTypes: [.qesApprovalRequest], merging: conflict) }
    }

    @Test func mixedFormatAssignmentsRespectAuthorizationAndOrder() throws {
        let transaction = try approval(ids: ["mdoc", "jwt"])
        let selections: CredentialSelectionSet = [
            try .init(credentialId: "m", docType: "pid", queryId: .init(value: "mdoc"), optionId: "option", claimQueries: []),
            try .init(credentialId: "j", docType: "pid", queryId: .init(value: "jwt"), optionId: "option", claimQueries: [])
        ]
        let authorized = try TransactionDataProcessor.assign([transaction], selections: selections, eligibleDocumentIds: ["m", "j"],
            mdocKeyAuthorizations: ["m": .init(nameSpaces: [namespace])], supportedTypes: [.qesApprovalRequest])
        #expect(authorized.first?.documentId == "m")
        let fallback = try TransactionDataProcessor.assign([transaction], selections: selections, eligibleDocumentIds: ["m", "j"],
            mdocKeyAuthorizations: ["m": .init()], supportedTypes: [.qesApprovalRequest])
        #expect(fallback.first?.documentId == "j")
        #expect(throws: (any Error).self) {
            try TransactionDataProcessor.assign([transaction], selections: selections, eligibleDocumentIds: ["m"],
                mdocKeyAuthorizations: ["m": .init()], supportedTypes: [.qesApprovalRequest])
        }
    }

    @Test func mdocParserDoesNotApplySdJwtHashNegotiation() throws {
        let original = try approval()
        var object = try #require(JSONSerialization.jsonObject(with: original.jsonData) as? [String: Any])
        object["transaction_data_hashes_alg"] = ["sha-512"]
        let encoded = try JSONSerialization.data(withJSONObject: object).base64URLEncodedString()
        let query = PresentationQuery.byDigitalCredentialsQuery(try .init(credentials: [
            .init(id: .init(value: "mdoc"), format: .MsoMdoc(), meta: ["doctype_value": "pid"])
        ]))
        _ = try TransactionData.parse(encoded, supportedTypes: [.qesApprovalRequest], presentationQuery: query).get()
        let transaction = try PresentationTransactionData(encodedValue: encoded)
        _ = try MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: .init(nameSpaces: [namespace]), supportedTypes: [.qesApprovalRequest])
        #expect(throws: (any Error).self) { try PresentationTransactionData.keyBindingClaims([transaction], supportedTypes: [.qesApprovalRequest]) }
    }

    @Test func deviceSignatureProtectsApprovalAndRejectsTampering() async throws {
        let transaction = try approval()
        let namespaces = try #require(try MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: .init(nameSpaces: [namespace]), supportedTypes: [.qesApprovalRequest]))
        let area = SoftwareSecureArea.create(storage: InMemorySecureKeyStorage())
        var privateKey = try await CoseKeyPrivate(secureArea: area, keyOptions: KeyOptions(curve: .P256))
        let publicKey = try await privateKey.key
        let transcript = SessionTranscript(handOver: OpenId4VpUtils.generateOpenId4VpHandover(clientId: "verifier", responseUri: "https://example.org/response", nonce: "nonce"))
        let auth = MdocAuthentication(sessionTranscript: transcript, authKeys: .init(publicKey: nil, privateKey: privateKey))
        let deviceAuth = try #require(try await auth.getDeviceAuthForTransfer(docType: "pid", dauthMethod: .deviceSignature,
            deviceNameSpaces: namespaces, unlockData: nil, authenticationContext: ThreadSafeAuthContext()))
        guard case .map(let authMap) = deviceAuth.toCBOR(options: CBOROptions()) else { Issue.record("Missing deviceAuth"); return }
        let signature = try #require(authMap[.utf8String("deviceSignature")].flatMap { Cose(type: .sign1, cbor: $0) })
        let payload = CBOR.array([.utf8String("DeviceAuthentication"), transcript.toCBOR(options: CBOROptions()), .utf8String("pid"), namespaces.toCBOR(options: CBOROptions()).taggedEncoded])
        #expect(try signature.validateDetachedCoseSign1(payloadData: Data(payload.taggedEncoded.encode()), publicKey_x963: publicKey.x963Representation))
        let altered = DeviceNameSpaces(deviceNameSpaces: [namespace: .init(deviceSignedItems: ["qesApproval": .byteString([0])])])
        let tampered = CBOR.array([.utf8String("DeviceAuthentication"), transcript.toCBOR(options: CBOROptions()), .utf8String("pid"), altered.toCBOR(options: CBOROptions()).taggedEncoded])
        #expect(try !signature.validateDetachedCoseSign1(payloadData: Data(tampered.taggedEncoded.encode()), publicKey_x963: publicKey.x963Representation))
        #expect(throws: (any Error).self) { try MdocTransactionData.validateResponse(.init(), docType: "pid", expected: namespaces) }
    }
}

private actor MdocTransactionTestSecureArea: SecureArea {
    static let name = "MdocTransactionTest"
    static let supportedEcCurves: [CoseEcCurve] = [.P256]
    static let shared = MdocTransactionTestSecureArea(storage: InMemorySecureKeyStorage())
    private let base: SoftwareSecureArea
    init(storage: any SecureKeyStorage) { base = .create(storage: storage) }
    nonisolated static func create(storage: any SecureKeyStorage) -> Self { .init(storage: storage) }
    func createKeyBatch(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?) async throws -> [CoseKey] {
        try await base.createKeyBatch(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions)
    }
    func getPublicKey(id: String, index: Int, curve: CoseEcCurve) async throws -> CoseKey { try await base.getPublicKey(id: id, index: index, curve: curve) }
    func deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) async throws { try await base.deleteKeyBatch(id: id, startIndex: startIndex, batchSize: batchSize) }
    func deleteKeyInfo(id: String) async throws { try await base.deleteKeyInfo(id: id) }
    func signature(id: String, index: Int, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?, authenticationContext: ThreadSafeAuthContext) async throws -> Data {
        try await base.signature(id: id, index: index, algorithm: algorithm, dataToSign: dataToSign, unlockData: unlockData, authenticationContext: authenticationContext)
    }
    func keyAgreement(id: String, index: Int, publicKey: CoseKey, unlockData: Data?, authenticationContext: ThreadSafeAuthContext) async throws -> SharedSecret {
        try await base.keyAgreement(id: id, index: index, publicKey: publicKey, unlockData: unlockData, authenticationContext: authenticationContext)
    }
    func getStorage() async -> any SecureKeyStorage { await base.getStorage() }
}

private actor MdocTransactionNetwork: Networking {
    var bodies: [String] = []
    func data(from url: URL) async throws -> (Data, URLResponse) { throw URLError(.unsupportedURL) }
    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        bodies.append(String(decoding: request.httpBody ?? Data(), as: UTF8.self))
        return (Data("{}".utf8), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
    }
}

extension MdocTransactionDataTests {
    @Test(arguments: ["approved", "unauthorized", "conflict", "declined", "missingKey"])
    func serviceConsentResponseAndErrors(scenario: String) async throws {
        let id = UUID().uuidString
        let area = MdocTransactionTestSecureArea.shared
        SecureAreaRegistry.shared.register(secureArea: area)
        let publicKey = try #require(try await area.createKeyBatch(id: id, credentialOptions: .init(credentialPolicy: .rotateUse, batchSize: 1), keyOptions: .init(curve: .P256)).first)
        let source = try #require(Data(name: "mdoc-mdl", ext: "txt", from: Bundle.module))
        let bytes = try #require(Data(base64URLEncoded: String(decoding: source, as: UTF8.self).removeWhitespaceAndNewlines()))
        let original = try IssuerSigned(data: Array(bytes))
        // Synthetic issuer fixture: replace only the device key/authorizations. This test
        // exercises holder signing and dispatch, not issuer signature verification.
        guard case .map(var msoMap) = original.issuerAuth.mso.toCBOR(options: CBOROptions()) else { Issue.record("Missing MSO"); return }
        let authorization: KeyAuthorizations? = scenario == "unauthorized" ? nil : .init(dataElements: [namespace: ["qesApproval"]])
        msoMap[.utf8String("deviceKeyInfo")] = DeviceKeyInfo(deviceKey: publicKey, keyAuthorizations: authorization).toCBOR(options: CBOROptions())
        let mso = try MobileSecurityObject(cbor: .map(msoMap))
        let auth = IssuerAuth(mso: mso, msoRawData: CBOR.map(msoMap).taggedEncoded.encode(), verifyAlgorithm: original.issuerAuth.verifyAlgorithm,
            signature: original.issuerAuth.signature, x5chain: original.issuerAuth.x5chain, statusList: nil)
        let fixture = IssuerSigned(issuerNameSpaces: original.issuerNameSpaces, issuerAuth: auth)
        let transaction = try approval()
        var url = URLComponents(string: "openid4vp://authorize")!
        let query = #"{"credentials":[{"id":"mdoc","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]}"#
        url.queryItems = [
            .init(name: "client_id", value: "redirect_uri:https://example.org/response"),
            .init(name: "response_uri", value: "https://example.org/response"), .init(name: "response_type", value: "vp_token"),
            .init(name: "response_mode", value: "direct_post"), .init(name: "nonce", value: "nonce"),
            .init(name: "dcql_query", value: query), .init(name: "transaction_data", value: String(decoding: try JSONEncoder().encode([transaction.encodedValue]), as: UTF8.self))
        ]
        #if canImport(EudiEtsi1196x2)
        let trust = TrustConfiguration(trustSource: .etsi(.eudiRef))
        #else
        let trust = TrustConfiguration(rootIaca: [])
        #endif
        let parameters = InitializeTransferData(dataFormats: [id: DocDataFormat.cbor.rawValue], documentData: [id: Data(fixture.encode(options: CBOROptions()))],
            documentKeyIndexes: [id: 0], docMetadata: [:], docDisplayNames: [:],
            docKeyInfos: scenario == "missingKey" ? [:] : [id: DocKeyInfo(secureAreaName: MdocTransactionTestSecureArea.name, batchSize: 1, credentialPolicy: .rotateUse).toData()],
            trustValidator: trust.accessTrustManager, deviceAuthMethod: "deviceSignature", idsToDocTypes: [id: mso.docType], hashingAlgs: [:], bleTransferMode: .server)
        let network = MdocTransactionNetwork()
        let service = try await OpenId4VpService(parameters: parameters, qrCode: Data(url.string!.utf8),
            openID4VpConfig: .init(supportedTransactionDataTypes: [.qesApprovalRequest], validateRegistrationCertificate: false),
            networking: network, trustConfig: trust, wrpRegistrationValidator: .init(trustConfig: trust))
        do {
            let option = try #require(try await service.receiveRequest().first)
            #expect(scenario != "unauthorized" && scenario != "missingKey")
            let name = try #require(option.requestName)
            #expect(service.transactionDataByRequest[name]?[id]?.map(\.encodedValue) == [transaction.encodedValue])
            let namespaces: RequestDeviceNameSpaces? = scenario == "conflict" ? [id: .init(deviceNameSpaces: [namespace: .init(deviceSignedItems: ["qesApproval": .byteString([0])])])] : nil
            try await service.sendResponse(userAccepted: scenario != "declined", itemsToSend: option.itemsRequested, deviceNameSpacesToSend: namespaces,
                authenticationContext: ThreadSafeAuthContext(), requestName: name, onSuccess: nil)
            #expect(scenario != "conflict")
        } catch let error as WalletError {
            #expect(["unauthorized", "conflict", "missingKey"].contains(scenario))
            #expect(error.code == .invalidTransactionData)
        }
        let bodies = await network.bodies
        #expect(bodies.count == 1)
        let fields = URLComponents(string: "https://example.org/?" + (bodies.first ?? ""))?.queryItems ?? []
        if scenario == "approved" {
            let vp = try #require(fields.first { $0.name == "vp_token" }?.value)
            let tokens = try JSONDecoder().decode([String: [String]].self, from: Data(vp.utf8))
            let encoded = try #require(tokens["mdoc"]?.first)
            let response = try DeviceResponse(data: Array(try #require(Data(base64URLEncoded: encoded))))
            let expected = try #require(try MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: authorization, supportedTypes: [.qesApprovalRequest]))
            try MdocTransactionData.validateResponse(response, docType: mso.docType, expected: expected)
            let document = try #require(response.documents?.first)
            guard case .map(let signed) = document.deviceSigned.toCBOR(options: CBOROptions()),
                  case .map(let authMap) = signed[.utf8String("deviceAuth")] else { Issue.record("Missing device signature"); return }
            let signature = try #require(authMap[.utf8String("deviceSignature")].flatMap { Cose(type: .sign1, cbor: $0) })
            let transcript = try #require(service.sessionTranscript)
            let payload = CBOR.array([.utf8String("DeviceAuthentication"), transcript.toCBOR(options: CBOROptions()), .utf8String(mso.docType), expected.toCBOR(options: CBOROptions()).taggedEncoded])
            #expect(try signature.validateDetachedCoseSign1(payloadData: Data(payload.taggedEncoded.encode()), publicKey_x963: publicKey.x963Representation))
        } else {
            #expect(fields.first { $0.name == "error" }?.value == (scenario == "declined" ? "access_denied" : "invalid_transaction_data"))
            #expect(fields.allSatisfy { $0.name != "vp_token" })
        }
        guard case .presentation(let log) = service.transactionLog else { Issue.record("Missing log"); return }
        #expect(log.transactionalData?.content.count == 1)
        if scenario == "approved" { #expect(log.transactionResult == .completed) }
        if scenario == "declined" { #expect(log.transactionResult == .notCompleted) }
    }
}
