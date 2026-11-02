import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import Testing
import eudi_lib_sdjwt_swift
@testable import EudiWalletKit

@Suite("Transaction log utility coverage")
struct TransactionLogUtilityCoverageTests {
    @Test("Maps qualified identifiers and rejects values without recognized prefixes")
    func qualifiedIdentifierMappings() {
        #expect(TransactionLogUtils.toQualifiedIdentifier("LEI-123") == .init(type: QualifiedIdentifier.lei, value: "123"))
        #expect(TransactionLogUtils.toQualifiedIdentifier("vat-GB123") == .init(type: QualifiedIdentifier.vatin, value: "GB123"))
        #expect(TransactionLogUtils.toQualifiedIdentifier("NTR-DE-456") == .init(type: QualifiedIdentifier.euid, value: "DE-456"))
        #expect(TransactionLogUtils.toQualifiedIdentifier("EOR-789") == .init(type: QualifiedIdentifier.eori, value: "789"))
        #expect(TransactionLogUtils.toQualifiedIdentifier("EXC-101") == .init(type: QualifiedIdentifier.excise, value: "101"))
        #expect(TransactionLogUtils.toQualifiedIdentifier("unknown-123") == nil)
        #expect(TransactionLogUtils.toQualifiedIdentifier("LEI") == nil)
        #expect(TransactionLogUtils.toQualifiedIdentifier("VAT-") == nil)
    }

    @Test("Builds registration party details from legal, personal, and fallback names")
    func registeredPartyFields() {
        let legal = WrpRegistrationPolicy(
            entitlements: [IssuerEntitlements.nonQEaa], sub: "LEI-123", country: "BE", credentials: [],
            purpose: [.init(lang: "en", value: "Access")], srvDescriptions: [[.init(lang: "fr", value: "Service")]],
            supportURI: "https://support.example", name: "Fallback Name", infoURI: "https://info.example",
            subLn: "Example Legal Entity"
        )
        #expect(TransactionLogUtils.interactingPartyName(legal) == "Example Legal Entity")
        #expect(TransactionLogUtils.interactingPartyContact(legal) == ["BE", "https://support.example", "https://info.example"])
        #expect(TransactionLogUtils.transactionPurposes(legal)?.map(\.content) == ["Access", "Service"])
        #expect(TransactionLogUtils.interactingPartyType(legal) == IssuerProviderType.nonQEaaProvider.rawValue)

        let personal = WrpRegistrationPolicy(sub: "subject", credentials: [], subGn: "Ada", subFn: "Lovelace")
        #expect(TransactionLogUtils.interactingPartyName(personal) == "Ada Lovelace")
        let displayFallback = WrpRegistrationPolicy(sub: "subject", credentials: [], name: "Registered display name")
        #expect(TransactionLogUtils.interactingPartyName(displayFallback) == "Registered display name")
        #expect(TransactionLogUtils.interactingPartyName(WrpRegistrationPolicy(sub: "subject", credentials: [])) == nil)
        #expect(TransactionLogUtils.interactingPartyContact(WrpRegistrationPolicy(sub: "subject", credentials: [])) == nil)
        #expect(TransactionLogUtils.transactionPurposes(WrpRegistrationPolicy(sub: "subject", credentials: [])) == nil)
        #expect(TransactionLogUtils.interactingPartyType(nil) == nil)

        for (entitlement, expectedType) in [
            (IssuerEntitlements.pid, IssuerProviderType.pidProvider),
            (IssuerEntitlements.qeaa, IssuerProviderType.qeaaProvider),
            (IssuerEntitlements.pubEaa, IssuerProviderType.pubEaaProvider)
        ] {
            let policy = WrpRegistrationPolicy(entitlements: [entitlement], sub: "subject", credentials: [])
            #expect(TransactionLogUtils.interactingPartyType(policy) == expectedType.rawValue)
        }
    }

    @Test("Merges CBOR request claims deterministically and removes duplicate paths")
    func mergesCborRequestClaims() {
        let path = MdocDataModel18013.ClaimPath([.claim(name: "ns"), .claim(name: "family_name")])
        let items: RequestItems = [
            "document-b": ["z-ns": [RequestItem(elementPath: ["claim"])], "a-ns": [RequestItem(elementPath: ["name"])]],
            "document-a": ["ns": [RequestItem(elementPath: ["family_name"]), RequestItem(elementPath: ["family_name"])]]
        ]
        let merged = TransactionLogUtils.parseCborClaims(items, idsToDocTypes: ["document-a": "pid", "document-b": "mdl"])
        #expect(merged.map(\.credentialIdentifier) == ["mdl", "pid"])
        #expect(merged.first?.claims == [
            MdocDataModel18013.ClaimPath([.claim(name: "a-ns"), .claim(name: "name")]),
            MdocDataModel18013.ClaimPath([.claim(name: "z-ns"), .claim(name: "claim")])
        ])
        #expect(merged.last?.claims == [path])
    }

    @Test("Logs only disclosed SD-JWT claim paths")
    func parsesPresentedSdJwtClaims() throws {
        let data = try #require(Data(name: "sjwt-pid-de", ext: "txt", from: Bundle.module))
        let token = try #require(String(data: data, encoding: .utf8)).trimmingCharacters(in: .whitespacesAndNewlines)
        let signed = try CompactParser().getSignedSdJwt(serialisedString: token)
        let claims = try TransactionLogUtils.parsePresentedClaims(signed, docType: "pid")
        #expect(claims.count == 1)
        #expect(claims.first?.credentialIdentifier == "pid")
        #expect(claims.first?.claims.isEmpty == false)
    }
}
