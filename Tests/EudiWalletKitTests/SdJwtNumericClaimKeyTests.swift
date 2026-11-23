import Testing
import Foundation
import CryptoKit
import MdocDataModel18013
import OpenID4VP
import WalletStorage
import eudi_lib_sdjwt_swift
import struct OpenID4VP.ClaimPath
import enum OpenID4VP.ClaimPathElement
@testable import EudiWalletKit

struct SdJwtNumericClaimKeyTests {

	private let pidId: WalletStorage.Document.ID = "pid"
	private let vct = "urn:eudi:pid:de:1"

	private func pidQueryable() throws -> DefaultDcqlQueryable {
		let data = try #require(Data(name: "sjwt-pid-de", ext: "txt", from: Bundle.module))
		let token = try #require(String(data: data, encoding: .utf8)).trimmingCharacters(in: .whitespacesAndNewlines)
		let sdJwt = try CompactParser().getSignedSdJwt(serialisedString: token)
		var claimPaths = [WalletStorage.Document.ID: [ClaimPath]]()
		var claimValues = [WalletStorage.Document.ID: [ClaimPath: [DCQLClaimValue]]]()
		OpenId4VpUtils.makeSdJwtClaimData(from: [pidId: sdJwt], claimPaths: &claimPaths, claimValues: &claimValues)
		return DefaultDcqlQueryable(credentials: [pidId: (vct, .sdjwt)], claimPaths: claimPaths, claimValues: claimValues)
	}

	private func ageOver(_ age: String) -> ClaimPath {
		ClaimPath([.claim(name: "age_equal_or_over"), .claim(name: age)])
	}

	@Test func numericObjectKeysAreMappedToClaimNames() throws {
		let queryable = try pidQueryable()
		let paths = queryable.getAllClaimPaths(id: pidId)
		#expect(paths.contains(ageOver("16")))
		#expect(!paths.contains(ClaimPath([.claim(name: "age_equal_or_over"), .arrayElement(index: 16)])))
		#expect(queryable.hasClaim(id: pidId, claimPath: ageOver("16")))
	}

	@Test func noncanonicalNumericObjectKeyDoesNotCreateCanonicalClaim() throws {
		let disclosure = Data(#"["salt", "016", true]"#.utf8).base64URLEncodedString()
		let digest = Data(SHA256.hash(data: Data(disclosure.utf8))).base64URLEncodedString()
		let header = Data(#"{"alg":"ES256"}"#.utf8).base64URLEncodedString()
		let payload = Data("""
		{"_sd_alg":"sha-256","age_equal_or_over":{"_sd":["\(digest)"]}}
		""".utf8).base64URLEncodedString()
		let signature = Data(repeating: 0, count: 64).base64URLEncodedString()
		let sdJwt = try CompactParser().getSignedSdJwt(serialisedString: "\(header).\(payload).\(signature)~\(disclosure)~")
		let recreated = try sdJwt.recreateClaims()
		#expect(recreated.recreatedClaims["age_equal_or_over"].dictionary?.keys.sorted() == ["016"])
		#expect(recreated.disclosuresPerClaimPath?.keys.contains {
			$0.value.last == .arrayElement(index: 16)
		} == true)

		var claimPaths = [WalletStorage.Document.ID: [ClaimPath]]()
		var claimValues = [WalletStorage.Document.ID: [ClaimPath: [DCQLClaimValue]]]()
		OpenId4VpUtils.makeSdJwtClaimData(from: [pidId: sdJwt], claimPaths: &claimPaths, claimValues: &claimValues)
		#expect(claimPaths[pidId]?.contains(ageOver("16")) == false)
		#expect(claimValues[pidId]?[ageOver("16")] == nil)
	}

	@Test func numericObjectKeysMatchRequestedValues() throws {
		let queryable = try pidQueryable()
		#expect(queryable.hasClaimWithValue(id: pidId, claimPath: ageOver("18"), values: [.boolean(true)]))
		#expect(queryable.hasClaimWithValue(id: pidId, claimPath: ageOver("65"), values: [.boolean(false)]))
		#expect(!queryable.hasClaimWithValue(id: pidId, claimPath: ageOver("65"), values: [.boolean(true)]))
	}

	@Test func arrayIndicesStayArrayElements() throws {
		let queryable = try pidQueryable()
		#expect(queryable.hasClaim(id: pidId, claimPath: ClaimPath([.claim(name: "nationalities"), .arrayElement(index: 0)])))
		#expect(!queryable.getAllClaimPaths(id: pidId).contains(ClaimPath([.claim(name: "nationalities"), .claim(name: "0")])))
	}

	@Test func requiredCredentialSetWithAgeClaimIsSatisfied() throws {
		let json = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:de:1"]},"claims":[{"path":["age_equal_or_over","16"]}]}],"credential_sets":[{"options":[["pid"]],"required":true}]}"#
		let dcql = try JSONDecoder().decode(DCQL.self, from: Data(json.utf8))
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: try pidQueryable())
		let selection = try #require(result.values.first?.first)
		#expect(selection.credentialId == pidId)
		#expect(selection.claimQueries.map(\.path) == [ageOver("16")])
	}
}
