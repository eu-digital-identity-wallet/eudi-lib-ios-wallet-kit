import Foundation
import Testing
import MdocDataModel18013
import MdocDataTransfer18013
import struct OpenID4VP.DCQL
import struct OpenID4VP.ClaimPath
@testable import EudiWalletKit

@Suite("Transaction entry logging")
struct TransactionEntryLoggingTests {
    @Test("Requested claims include every DCQL alternative, including unavailable credential types")
    func allAlternatives() throws {
        let dcql = try JSONDecoder().decode(DCQL.self, from: Data(#"""
        {
          "credentials": [
            {"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"pid"},
             "claims":[{"path":["ns","family_name"]}]},
            {"id":"alternative","format":"dc+sd-jwt","meta":{"vct_values":["vct-a","vct-b"]},
             "claims":[{"id":"address","path":["addresses",null,"street"]},
                       {"id":"email","path":["email"]}],
             "claim_sets":[["address"],["email"]]}
          ],
          "credential_sets":[{"options":[["pid"],["alternative"]]}]
        }
        """#.utf8))
        let entries = TransactionLogUtils.parseRequestedClaims(dcql)
        #expect(entries.map(\.credentialIdentifier) == ["pid", "vct-a", "vct-b"])
        for entry in entries where entry.credentialIdentifier.hasPrefix("vct") {
            #expect(entry.claims == [
                MdocDataModel18013.ClaimPath([.claim(name: "addresses"), .allArrayElements, .claim(name: "street")]),
                MdocDataModel18013.ClaimPath([.claim(name: "email")])
            ])
        }
    }

    @Test("Omitted DCQL claims expand across all matching wallet credentials")
    func allMatchingCredentials() throws {
        let dcql = try JSONDecoder().decode(DCQL.self, from: Data(#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"pid"}}]}"#.utf8))
        let queryable = DefaultDcqlQueryable(credentials: ["one": ("pid", .cbor), "two": ("pid", .cbor)],
            claimPaths: ["one": [ClaimPath([.claim(name: "ns"), .claim(name: "a")])],
                         "two": [ClaimPath([.claim(name: "ns"), .claim(name: "b")])]])
        let entries = TransactionLogUtils.parseRequestedClaims(dcql, queryable: queryable)
        #expect(entries.count == 1)
        #expect(entries.first?.claims.count == 2)
    }

    @Test("ClaimPath conversion preserves numeric names, indices, and wildcards")
    func claimPathRoundTrip() {
        let path = ClaimPath([.claim(name: "0"), .arrayElement(index: 2), .allArrayElements, .claim(name: "")])
        #expect(path.mdocClaimPath.openID4VPClaimPath == path)
    }

    @Test("Request metadata and identity survive incomplete and completed snapshots")
    func lifecycle() throws {
        var log = TransactionLogUtils.createEmptyPresentationLog()
        let identifier = log.transactionIdentifier
        let time = log.time
        let requested = [ClaimInfo(credentialIdentifier: "pid", claims: [.claim("name"), .claim("age")])]
        let policy = WrpRegistrationPolicy(sub: "LEIXG-123", credentials: [], purpose: [.init(lang: "en", value: "Age check")],
            registryURI: "https://registry.example", privacyPolicy: "https://rp.example/privacy", name: "Registered RP")
        TransactionLogUtils.withRequest(requested, policy: policy, name: "Certificate CN", transactionLog: &log)
        TransactionLogUtils.withResult(.notCompleted, reason: "User declined", transactionLog: &log)
        guard case .presentation(let incomplete) = log else { Issue.record("Expected presentation"); return }
        #expect(incomplete.listOfClaimsRequested == requested)
        #expect(incomplete.listOfClaimsPresented.isEmpty)
        #expect(incomplete.interactingPartyName?.content == "Registered RP")
        #expect(incomplete.interactingPartyIdentifier == .init(type: QualifiedIdentifier.lei, value: "123"))
        #expect(incomplete.reasonOfNoncompletion == "User declined")
        let presented = [ClaimInfo(credentialIdentifier: "pid", claims: [.claim("age")])]
        TransactionLogUtils.withResult(.completed, presented: presented, transactionLog: &log)
        #expect(log.transactionIdentifier == identifier)
        #expect(log.time == time)
        #expect(log.reasonOfNoncompletion == nil)
        guard case .presentation(let completed) = log else { Issue.record("Expected presentation"); return }
        #expect(completed.listOfClaimsPresented == presented)
        #expect(completed.listOfClaimsRequested == requested)
        #expect(completed.purpose == incomplete.purpose)
        #expect(completed.privacyPolicy == incomplete.privacyPolicy)
        let encoded = try JSONEncoder().encode(log)
        let decoded = try JSONDecoder().decode(TransactionEntry.self, from: encoded)
        #expect(decoded.transactionIdentifier == log.transactionIdentifier)
        #expect(decoded.transactionResult == log.transactionResult)
        #expect(abs(decoded.time.timeIntervalSince(log.time)) < 1)
        let json = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(json["rawResponse"] == nil)
        #expect(json["rawRequest"] == nil)
        #expect(json["transactionResult"] as? String == "Completed")
    }

    @Test("mdoc element identifiers containing dots remain a single claim component")
    func mdocNames() {
        let items: RequestItems = ["document-id": ["ns": [RequestItem(elementPath: ["given.name"])]]]
        let claims = TransactionLogUtils.parseCborClaims(items, idsToDocTypes: ["document-id": "pid"])
        #expect(claims == [ClaimInfo(credentialIdentifier: "pid", claims: [
            MdocDataModel18013.ClaimPath([.claim(name: "ns"), .claim(name: "given.name")])
        ])])
    }

    @Test("Registered legal name takes precedence over display name")
    func registeredPartyName() {
        let policy = WrpRegistrationPolicy(sub: "LEI:123", credentials: [], name: "Display name", subLn: "Legal name")
        #expect(TransactionLogUtils.interactingPartyName(policy) == "Legal name")
    }

    @Test("Credential issuer fields retain the issuer name and qualified identifier")
    func credentialIssuerFields() {
        let qualified = TransactionLogUtils.credentialIssuer(name: "Example Issuer", identifier: "LEI-123")
        #expect(qualified.name?.content == "Example Issuer")
        #expect(qualified.identifier == .init(type: QualifiedIdentifier.lei, value: "123"))

        let url = TransactionLogUtils.credentialIssuer(name: nil, identifier: "https://issuer.example")
        #expect(url.name?.content == "https://issuer.example")
        #expect(url.identifier == nil)
    }

    @Test("Verifier certificate subject takes precedence over its CA-derived legal name")
    func verifierCertificateName() {
        let name = TransactionLogUtils.verifierName(
            legalName: "Example CA",
            certificateSubject: "C=CY, O=Example Verifier, CN=verifier.example")
        #expect(name == "verifier.example")
        #expect(TransactionLogUtils.verifierName(legalName: "Pre-registered verifier", certificateSubject: nil) == "Pre-registered verifier")
    }

    @Test("Request failure is persisted under the original transaction identifier")
    func requestFailure() async {
        let recorder = RecordingTransactionLogger()
        let service = FaultPresentationService(msg: "Invalid request")
        let requested = [ClaimInfo(credentialIdentifier: "unavailable-pid", claims: [.claim("age")])]
        TransactionLogUtils.withRequest(requested, policy: nil, name: "RP", transactionLog: &service.transactionLog)
        let session = PresentationSession(presentationService: service, docIdToPresentInfo: [:], documentKeyIndexes: [:],
            userAuthenticationRequired: false, localAuthenticationContext: ThreadSafeAuthContext(), transactionLogger: recorder)
        let request = await session.receiveRequest()
        #expect(request == nil)
        let snapshots = await recorder.snapshots
        #expect(snapshots.count >= 2)
        #expect(Set(snapshots.map(\.transactionIdentifier)).count == 1)
        #expect(snapshots.last?.transactionResult == .notCompleted)
        #expect(snapshots.last?.reasonOfNoncompletion == "Invalid request")
        if case .presentation(let last)? = snapshots.last {
            #expect(last.listOfClaimsRequested == requested)
            #expect(last.listOfClaimsPresented.isEmpty)
        } else { Issue.record("Missing presentation entry") }
    }
}

private actor RecordingTransactionLogger: TransactionLogger {
    var snapshots: [TransactionEntry] = []
    func log(transaction: TransactionEntry) async throws { snapshots.append(transaction) }
}
