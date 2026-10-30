import CryptoKit
import Foundation
import OrderedCollections
import SwiftyJSON
import Testing
import eudi_lib_sdjwt_swift
import MdocDataModel18013
import MdocDataTransfer18013
@testable import EudiWalletKit

@Suite("SD-JWT utility coverage")
struct SdJwtCoverageTests {
    @Test("Resolves nested object disclosures and selectively disclosed array values")
    func resolvesNestedAndArrayDisclosures() throws {
        let emailDisclosure = disclosure(["salt-email", "email", "alice@example.test"])
        let nameDisclosure = disclosure(["salt-name", "name", "Alice"])
        let firstRoleDisclosure = disclosure(["salt-role", "admin"])
        let emailHash = disclosureHash(emailDisclosure, algorithm: "sha-256")
        let nameHash = disclosureHash(nameDisclosure, algorithm: "sha-256")
        let roleHash = disclosureHash(firstRoleDisclosure, algorithm: "sha-256")
        let payload = JSON(parseJSON: """
        {"_sd":["\(emailHash)"],"_sd_alg":"sha-256","profile":{"_sd":["\(nameHash)"],"_sd_alg":"sha-256"},"roles":[{"...":"\(roleHash)"},{"...":"not-disclosed"},"reader"]}
        """)

        let resolved = SdJwtUtils.resolveNestedSdClaims(
            payload,
            disclosures: [emailDisclosure, nameDisclosure, firstRoleDisclosure, "not*valid-base64url!"],
            hashingAlg: "sha-256"
        )

        #expect(resolved["email"].string == "alice@example.test")
        #expect(resolved["profile"]["name"].string == "Alice")
        #expect(resolved["roles"].arrayValue.map(\.stringValue) == ["admin", "reader"])
        #expect(resolved["_sd"].exists() == false)
        #expect(resolved["_sd_alg"].exists() == false)
        #expect(resolved["profile"]["_sd"].exists() == false)
    }

    @Test("Uses the requested digest algorithm and falls back to SHA-256 for an unknown name")
    func resolvesDisclosureWithEachDigestAlgorithm() {
        for algorithm in ["sha-384", "sha-512", "future-hash"] {
            let disclosure = self.disclosure(["salt", "city", "Paris"])
            let hash = disclosureHash(disclosure, algorithm: algorithm == "future-hash" ? "sha-256" : algorithm)
            let payload = JSON(["_sd": [hash]])
            let resolved = SdJwtUtils.resolveNestedSdClaims(payload, disclosures: [disclosure], hashingAlg: algorithm)
            #expect(resolved["city"].string == "Paris")
        }
    }

    @Test("Ignores malformed and short object disclosures and drops unmatched array disclosures")
    func ignoresInvalidDisclosures() {
        let shortDisclosure = disclosure(["salt-only"])
        let shortHash = disclosureHash(shortDisclosure, algorithm: "sha-256")
        let payload = JSON(parseJSON: """
        {"_sd":["\(shortHash)","missing"],"list":[{"...":"missing"}, {"...":"\(shortHash)"}]}
        """)

        let resolved = SdJwtUtils.resolveNestedSdClaims(
            payload,
            disclosures: [shortDisclosure, "!not-ascii-☃"],
            hashingAlg: "sha-256"
        )

        #expect(resolved["_sd"].exists() == false)
        #expect(resolved["list"].arrayValue.isEmpty)
    }

    @Test("Splits compact JWTs with missing segments safely")
    func extractsCompactJwtParts() {
        #expect(SdJwtUtils.extractJWTParts("header.payload.signature").0 == "header")
        #expect(SdJwtUtils.extractJWTParts("header.payload.signature").1 == "payload")
        #expect(SdJwtUtils.extractJWTParts("header.payload.signature").2 == "signature")
        #expect(SdJwtUtils.extractJWTParts("").0 == "")
        #expect(SdJwtUtils.extractJWTParts("header").1 == "")
        #expect(SdJwtUtils.extractJWTParts("header.payload").2 == "")
    }

    @Test("Parses a single JWK, a JWK array, and the jwks keys form")
    func parsesConfirmationBindingKeys() throws {
        let first = JSON(["kty": "EC", "crv": "P-256", "x": "AQ", "y": "Ag"])
        let second = JSON(["kty": "EC", "crv": "P-384", "x": "Aw", "y": "BA"])
        let third = JSON(["kty": "EC", "crv": "P-521", "x": "BQ", "y": "Bg"])

        #expect(try SdJwtUtils.parseCnfBindingKeys(JSON(["jwk": first])).count == 1)
        #expect(try SdJwtUtils.parseCnfBindingKeys(JSON(["jwk": [first, second]])).count == 2)
        #expect(try SdJwtUtils.parseCnfBindingKeys(JSON(["jwks": ["keys": [third]]])).count == 1)
        #expect(try SdJwtUtils.parseCnfBindingKeys(JSON(["jwk": first, "jwks": ["keys": [second]]])).count == 2)
    }

    @Test("Rejects invalid confirmation claims and malformed compact credentials")
    func rejectsInvalidConfirmationKeys() throws {
        #expect(throws: WalletError.self) { try SdJwtUtils.parseCnfBindingKeys(JSON([:])) }
        #expect(throws: WalletError.self) {
            try SdJwtUtils.parseCnfBindingKeys(JSON(["jwk": ["kty": "RSA", "crv": "P-256", "x": "AQ", "y": "Ag"]]))
        }
        #expect(throws: WalletError.self) {
            try SdJwtUtils.parseCnfBindingKeys(JSON(["jwk": ["kty": "EC", "crv": "P-256", "x": "AQ"]]))
        }
        #expect(throws: (any Error).self) { try SdJwtUtils.parseCnfBindingKeys(fromSerializedCredential: "header.not-base64.signature") }
        #expect(throws: WalletError.self) {
            try SdJwtUtils.parseCnfBindingKeys(fromSerializedCredential: compactToken(payload: ["sub": "no key confirmation"]))
        }
        #expect(throws: WalletError.self) { try SdJwtUtils.parseCnfBindingKeys(fromDocumentData: Data([0xff, 0xfe])) }
    }

    @Test("Reads confirmation keys from a compact credential payload")
    func parsesKeysFromSerializedCredential() throws {
        let key = ["kty": "EC", "crv": "P-256", "x": "AQ", "y": "Ag"]
        let token = compactToken(payload: ["cnf": ["jwk": key]])
        #expect(try SdJwtUtils.parseCnfBindingKeys(fromSerializedCredential: token).count == 1)
        #expect(try SdJwtUtils.parseCnfBindingKeys(fromDocumentData: Data(token.utf8)).count == 1)
    }

    private func disclosure(_ value: [Any]) -> String {
        base64URL(try! JSON(value).rawData())
    }

    private func disclosureHash(_ disclosure: String, algorithm: String) -> String {
        let input = Data(disclosure.utf8)
        let digest: Data
        switch algorithm {
        case "sha-384": digest = Data(SHA384.hash(data: input))
        case "sha-512": digest = Data(SHA512.hash(data: input))
        default: digest = Data(SHA256.hash(data: input))
        }
        return base64URL(digest)
    }

    private func compactToken(payload: [String: Any]) -> String {
        "e30.\(base64URL((try? JSONSerialization.data(withJSONObject: payload)) ?? Data())).signature"
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

@Suite("Credential disclosure element coverage")
struct CredentialElementCoverageTests {
    @Test("Builds nested SD-JWT element trees and filters unrequested document claims")
    func buildsNestedTree() {
        let streetClaim = docClaim(name: "street", path: ["address", "street"])
        let cityClaim = docClaim(name: "city", path: ["address", "city"])
        let ignoredClaim = docClaim(name: "postal_code", path: ["address", "postal_code"])
        let addressClaim = docClaim(name: "address", path: ["address"], children: [streetClaim, cityClaim, ignoredClaim])
        let paths = OrderedSet([
            ClaimPath([eudi_lib_sdjwt_swift.ClaimPathElement.claim(name: "address"), .claim(name: "street")]),
            ClaimPath([eudi_lib_sdjwt_swift.ClaimPathElement.claim(name: "address"), .claim(name: "city")])
        ])
        let requested = [
            RequestItem(elementPath: ["address", "street"], intentToRetain: true),
            RequestItem(elementPath: ["address", "city"]),
            RequestItem(elementPath: [])
        ]

        let tree = SignedSDJWT.buildSdJwtElementTree(
            itemsReq: requested,
            allPaths: paths,
            docClaims: [addressClaim],
            isMandatory: { $0.elementPath.last == "street" },
            parentPath: []
        )

        #expect(tree.count == 1)
        let address = tree[0]
        #expect(address.elementPath == ["address"])
        #expect(!address.isOptional)
        #expect(address.nestedElements?.map { $0.elementPath } == [["address", "street"], ["address", "city"]])
        #expect(address.docClaim?.children?.map { $0.name } == ["street", "city"])
        #expect(address.nestedElements?.first?.isOptional == false)
        #expect(address.nestedElements?.first?.intentToRetain == true)
        #expect(address.nestedElements?.allSatisfy { $0.isValid } == true)
    }

    @Test("Handles exact root requests, unknown paths, invalid selections, and empty paths")
    func buildsLeafAndSelectionModels() {
        let leaf = docClaim(name: "email", path: ["email"])
        let allPaths = OrderedSet([ClaimPath([eudi_lib_sdjwt_swift.ClaimPathElement.claim(name: "email")])])
        let tree = SignedSDJWT.buildSdJwtElementTree(
            itemsReq: [RequestItem(elementPath: ["email"]), RequestItem(elementPath: ["missing"])],
            allPaths: allPaths,
            docClaims: [leaf],
            isMandatory: { _ in false },
            parentPath: []
        )
        #expect(tree.count == 2)
        #expect(tree[0].isValid)
        #expect(!tree[1].isValid)
        #expect(tree[0].docClaim?.name == "email")

        let child = SdJwtElement(elementPath: ["email"], isOptional: true, stringValue: "a@example.test", docClaim: leaf, isValid: true)
        let hiddenChild = SdJwtElement(elementPath: ["phone"], isOptional: true, stringValue: nil, docClaim: nil, isValid: false)
        let unselectedChild = SdJwtElement(elementPath: ["birth_date"], isOptional: true, stringValue: nil, docClaim: nil, isValid: true, isSelected: false)
        let parent = SdJwtElement(elementPath: ["identity"], isOptional: false, stringValue: nil, docClaim: nil, isValid: true, nestedElements: [child, hiddenChild, unselectedChild])
        let collection = SdJwtElements(docId: "doc", vct: "identity", sdJwtElements: [parent])

        #expect(collection.id == "doc")
        #expect(collection.selectedItemsDictionary[""]?.map(\.elementPath) == [["identity"], ["email"]])
        #expect(DocElements.sdJwt(collection).isSdJwt)
        #expect(DocElements.sdJwt(collection).docTypeOrVct == "identity")
        #expect(DocElements.sdJwt(collection).selectedItemsDictionary[""]?.count == 2)
        #expect(RequestItem(elementPath: ["people", "0", ""]).claimPath.value.count == 3)
    }

    @Test("Maps mdoc element selection to request items")
    func mapsMdocSelection() {
        let valid = MsoMdocElement(elementIdentifier: "family_name", isOptional: false, intentToRetain: true, stringValue: "Doe", docClaim: nil, isValid: true)
        let invalid = MsoMdocElement(elementIdentifier: "portrait", isOptional: true, stringValue: nil, docClaim: nil, isValid: false)
        let notSelected = MsoMdocElement(elementIdentifier: "birth_date", isOptional: true, stringValue: nil, docClaim: nil, isValid: true, isSelected: false)
        let collection = MsoMdocElements(docId: "pid-1", docType: "pid", displayName: "PID", nameSpacedElements: [NameSpacedElements(nameSpace: "ns", elements: [valid, invalid, notSelected])])

        #expect(valid.isValidAndSelected)
        #expect(!invalid.isValidAndSelected)
        #expect(!notSelected.isValidAndSelected)
        #expect(collection.selectedItemsDictionary["ns"]?.map(\.elementIdentifier) == ["family_name"])
        #expect(collection.selectedItemsDictionary["ns"]?.first?.intentToRetain == true)
        #expect(DocElements.msoMdoc(collection).isMsoMdoc)
        #expect(DocElements.msoMdoc(collection).docId == "pid-1")
        #expect(DocElements.msoMdoc(collection).docTypeOrVct == "pid")
    }

    private func docClaim(name: String, path: [String], children: [DocClaim]? = nil) -> DocClaim {
        DocClaim(name: name, path: path, displayName: nil, dataValue: .string(name), stringValue: name, isOptional: true, order: 0, namespace: nil, children: children)
    }
}
