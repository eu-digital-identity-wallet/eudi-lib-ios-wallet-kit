import CryptoKit

import Foundation

import MdocDataModel18013

import OpenID4VP

/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import SwiftCBOR

import Testing

import WalletStorage

import eudi_lib_sdjwt_swift

import struct OpenID4VP.ClaimPath

import enum OpenID4VP.ClaimPathElement

@testable import EudiWalletKit

@testable import JOSESwift

struct DcqlQueryTests {

	fileprivate func getMdocClaims(_ namespace: String, _ claimTypes: [String]) -> [ClaimPath] {
		claimTypes.map { claimType in ClaimPath([.claim(name: namespace), .claim(name: claimType)])
		}
	}

	fileprivate func getSdjwtClaims(_ claimPaths: [[String]]) -> [ClaimPath] {
		claimPaths.map { claimPath in
			ClaimPath(claimPath.map { ClaimPathElement.claim(name: $0) })
		}
	}

	/// Helper method to load test resources
	private func loadTestResource(fileName: String, ext: String = "json") throws -> Data {
		// Remove extension if already included in fileName
		let name =
			fileName.hasSuffix(".\(ext)") ? String(fileName.dropLast(ext.count + 1)) : fileName
		guard let data = Data(name: name, ext: ext, from: Bundle.module) else {
			throw NSError(
				domain: "TestError", code: 1,
				userInfo: [NSLocalizedDescriptionKey: "Resource file not found: \(name).\(ext)"])
		}
		return data
	}

	/// Loads a single resource file and returns parsed credential data with a given index suffix on the credential ID.
	private func loadDcqlQueryable(resourceFileName: String, index: Int, ext: String = "txt") throws
		-> (
			id: WalletStorage.Document.ID, docType: DocType, format: DocDataFormat,
			cbor: IssuerSigned?, sdJwt: SignedSDJWT?
		)
	{
		let data = try loadTestResource(fileName: resourceFileName, ext: ext)
		let credentialId: WalletStorage.Document.ID = "\(resourceFileName)-\(index)"
		if resourceFileName.hasPrefix("mdoc-") {
			guard let strData = String(data: data, encoding: .utf8) else {
				throw NSError(
					domain: "TestError", code: 2,
					userInfo: [
						NSLocalizedDescriptionKey:
							"Invalid UTF-8 in resource: \(resourceFileName).\(ext)"
					])
			}
			guard let base64Data = Data(base64URLEncoded: strData.removeWhitespaceAndNewlines())
			else {
				throw NSError(
					domain: "TestError", code: 3,
					userInfo: [
						NSLocalizedDescriptionKey:
							"Invalid base64url mdoc payload in resource: \(resourceFileName).\(ext)"
					])
			}
			let issuerSigned = try IssuerSigned(data: [UInt8](base64Data))
			let docType = issuerSigned.issuerAuth.mso.docType
			return (credentialId, docType, .cbor, issuerSigned, nil)
		} else {
			guard
				let sdJwtString = String(data: data, encoding: .utf8)?.trimmingCharacters(
					in: .whitespacesAndNewlines)
			else {
				throw NSError(
					domain: "TestError", code: 4,
					userInfo: [
						NSLocalizedDescriptionKey:
							"Invalid UTF-8 in resource: \(resourceFileName).\(ext)"
					])
			}
			let parser = CompactParser()
			let signedSdJwt = try parser.getSignedSdJwt(serialisedString: sdJwtString)
			let recreatedClaims = try signedSdJwt.recreateClaims().recreatedClaims
			guard let docType = recreatedClaims["vct"].string ?? recreatedClaims["type"].string
			else {
				throw NSError(
					domain: "TestError", code: 5,
					userInfo: [
						NSLocalizedDescriptionKey:
							"Missing vct/type in SD-JWT resource: \(resourceFileName).\(ext)"
					])
			}
			return (credentialId, docType, .sdjwt, nil, signedSdJwt)
		}
	}

	/// Builds one queryable from all provided resource files.
	private func loadDcqlQueryables(resourceFileNames: [String], ext: String = "txt") throws
		-> DefaultDcqlQueryable
	{
		var idsToDocTypes = [WalletStorage.Document.ID: DocType]()
		var formatsRequested = [DocType: DocDataFormat]()
		var docsCbor = [WalletStorage.Document.ID: IssuerSigned]()
		var docsSdJwt = [WalletStorage.Document.ID: SignedSDJWT]()

		for (index, fileName) in resourceFileNames.enumerated() {
			let parsed = try loadDcqlQueryable(resourceFileName: fileName, index: index, ext: ext)
			idsToDocTypes[parsed.id] = parsed.docType
			formatsRequested[parsed.docType] = parsed.format
			if let cbor = parsed.cbor { docsCbor[parsed.id] = cbor }
			if let sdJwt = parsed.sdJwt { docsSdJwt[parsed.id] = sdJwt }
		}

		let credentials = OpenId4VpUtils.makeCredentialMap(
			idsToDocTypes: idsToDocTypes, formatsRequested: formatsRequested)
		var claimPaths = [WalletStorage.Document.ID: [ClaimPath]]()
		var claimValues = [WalletStorage.Document.ID: [ClaimPath: [String]]]()
		OpenId4VpUtils.makeCborClaimData(
			from: docsCbor, claimPaths: &claimPaths, claimValues: &claimValues)
		OpenId4VpUtils.makeSdJwtClaimData(
			from: docsSdJwt, claimPaths: &claimPaths, claimValues: &claimValues)
		// construct a dcql queryable with all claims from all loaded resources
		return DefaultDcqlQueryable(
			credentials: credentials, claimPaths: claimPaths, claimValues: claimValues)
	}

	@Test("DCQL simple query - success case", arguments: ["dcql-vehicle"])
	func testDcqlQuerySimplificationSuccess(dcqlFile: String) throws {
		// Load DCQL from resource file
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let wrapper = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcql = try DCQL(credentials: wrapper.credentials)
		// Create a mock queryable that has matching credentials with both claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: ["cred1": ("org.iso.7367.1.mVRC", DocDataFormat.cbor)],
			claimPaths: [
				"cred1": [
					ClaimPath([.claim(name: "org.iso.7367.1"), .claim(name: "vehicle_holder")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "first_name")]),
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential query result")
		#expect(
			result.values.first?.first?.claimQueries.count == 2,
			"Should have both claim paths for cred1")
	}

	@Test("DCQL Document Number query - returns one credential")
	func testDcqlDocumentNumberQueryReturnsOneCredential() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-document-number")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable1 = try loadDcqlQueryables(resourceFileNames: ["sjwt-pid-kotlin"])
		let result1 = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable1)
		#expect(result1.count == 1, "Should resolve exactly one credential")
		let dcqlQueryable2 = try loadDcqlQueryables(resourceFileNames: ["sjwt-pid-python"])
		do {
			_ = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable2)
			Issue.record("Expected WalletError.claimNotFound to be thrown")
		} catch let error as WalletError {
			#expect(error.code == .claimNotFound, "Should fail with claimNotFound")
		}
		let dcqlQueryable3 = try loadDcqlQueryables(resourceFileNames: [
			"sjwt-pid-python", "sjwt-pid-kotlin",
		])
		let result3 = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable3)
		#expect(result3.count == 1, "Should resolve exactly one credential")
	}

	@Test("DCQL simple query - failure", arguments: ["dcql-vehicle"])
	func testDcqlQuerySimplificationPartialMatch(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let wrapper = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcql = try DCQL(credentials: wrapper.credentials)
		// Create a mock queryable that only has one of the two claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: ["cred1": ("org.iso.7367.1.mVRC", DocDataFormat.cbor)],
			claimPaths: [
				"cred1": [
					ClaimPath([.claim(name: "org.iso.7367.1"), .claim(name: "vehicle_holder")])
					// Missing first_name claim
				]
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test(
		"DCQL multiple pid with credential_sets - pass with first option",
		arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsFirstOption(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has the "pid" credential that satisfies the first option of the first credential_set
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["given_name"], ["family_name"], ["address", "street_address"],
				])
			]
		)

		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(
			result.values.first?.first?.claimQueries.count == 3,
			"Should have all three claims for pid")
	}

	@Test(
		"DCQL multiple credentials with credential_sets - pass with third option (multiple creds)",
		arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsThirdOption(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has both reduced credentials (third option of first credential_set)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"reduced_id": (
					"https://credentials.example.com/reduced_identity_credential",
					DocDataFormat.sdjwt
				),
				"residence": ("https://cred.example/residence_credential", DocDataFormat.sdjwt),
			],
			claimPaths: [
				"reduced_id": getSdjwtClaims([["given_name"], ["family_name"]]),
				"residence": getSdjwtClaims([["postal_code"], ["locality"], ["region"]]),
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one option combination")
		let combo = result.values.first
		#expect(combo?.count == 2, "Should have two credentials in the combination")
		#expect(
			combo?.first(where: { $0.credentialId == "reduced_id" })?.claimQueries.count == 2,
			"Should have two claims for reduced_id")
		#expect(
			combo?.first(where: { $0.credentialId == "residence" })?.claimQueries.count == 3,
			"Should have three claims for residence")
	}

	@Test(
		"DCQL multiple credentials with credential_sets - pass with optional credential",
		arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsWithOptional(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has "pid" and optional "nice_to_have" credential
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				),
				"rewards": ("https://company.example/company_rewards", DocDataFormat.sdjwt),
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["given_name"], ["family_name"], ["address", "street_address"],
				]),
				"rewards": getSdjwtClaims([["rewards_number"]]),
			]
		)

		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 2, "Should have two options: with and without optional")
		let pidOnly = result.values.first(where: { $0.count == 1 })
		let withOptional = result.values.first(where: { $0.count == 2 })
		#expect(pidOnly != nil, "Should have pid-only option")
		#expect(withOptional != nil, "Should have option with optional rewards")
		#expect(pidOnly?.first?.claimQueries.count == 3, "Should have three claims for pid_cred")
		#expect(
			withOptional?.first(where: { $0.credentialId == "rewards" })?.claimQueries.count == 1,
			"Should have one claim for rewards")
	}

	@Test(
		"DCQL multiple credentials with credential_sets - fail when required set not satisfied",
		arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsFailRequired(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet only has the optional credential, not any required ones
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"rewards": ("https://company.example/company_rewards", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"rewards": getSdjwtClaims([["rewards_number"]])
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test(
		"DCQL multiple credentials with credential_sets - fail when partial claims",
		arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsFailPartialClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has "pid" credential but missing one required claim
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["given_name"],
					["family_name"],
					// Missing address.street_address claim
				])
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test("DCQL mdl-or-photoid - pass with mDL", arguments: ["dcql-mdl-or-photoid"])
	func testDcqlMdlOrPhotoIdWithMdl(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has mDL with identity claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: ["mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor)],
			claimPaths: [
				"mdl_cred": getMdocClaims(
					"org.iso.18013.5.1", ["given_name", "family_name", "portrait"])
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(
			result.values.first?.first?.claimQueries.count == 3, "Should have three identity claims"
		)
	}

	@Test("DCQL mdl-or-photoid - pass with photo card", arguments: ["dcql-mdl-or-photoid"])
	func testDcqlMdlOrPhotoIdWithPhotoCard(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has photo ID card with identity claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: ["photo_cred": ("org.iso.23220.photoid.1", DocDataFormat.cbor)],
			claimPaths: [
				"photo_cred": getMdocClaims(
					"org.iso.18013.5.1", ["given_name", "family_name", "portrait"])
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(
			result.values.first?.first?.claimQueries.count == 3, "Should have three identity claims"
		)
	}

	@Test(
		"DCQL mdl-or-photoid - pass with photo card and address", arguments: ["dcql-mdl-or-photoid"]
	)
	func testDcqlMdlOrPhotoIdWithPhotoCardAndAddress(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has photo card with both identity and address claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: ["photo_cred": ("org.iso.23220.photoid.1", DocDataFormat.cbor)],
			claimPaths: [
				"photo_cred": getMdocClaims(
					IsoMdlModel.isoNamespace,
					[
						"given_name", "family_name", "portrait", "resident_address",
						"resident_country",
					])
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 2, "Should have two options: with and without address")
		// photo_cred satisfies the photo_card-id option (3 identity claims) plus photo_card-address option (2 more)
		#expect(
			result.values.contains(where: { $0.first?.credentialId == "photo_cred" }),
			"Should have photo credential")
	}

	@Test(
		"DCQL mdl-or-photoid - pass with both mDL and photo card prefers first",
		arguments: ["dcql-mdl-or-photoid"])
	func testDcqlMdlOrPhotoIdWithBoth(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has both mDL and photo card
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"photo_cred": ("org.iso.23220.photoid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"mdl_cred": getMdocClaims(
					"org.iso.18013.5.1", ["given_name", "family_name", "portrait"]),
				"photo_cred": getMdocClaims(
					"org.iso.18013.5.1", ["given_name", "family_name", "portrait"]),
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		// Both mDL and photo card satisfy their respective options; all are collected
		#expect(result.count >= 1, "Should have at least one option")
		#expect(
			result.values.contains(where: { $0.contains(where: { $0.credentialId == "mdl_cred" }) }
			), "mDL credential should be included")
	}

	@Test(
		"DCQL mdl-or-photoid - fail with partial identity claims",
		arguments: ["dcql-mdl-or-photoid"])
	func testDcqlMdlOrPhotoIdFailPartialClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has mDL but missing required claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: ["mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor)],
			claimPaths: [
				"mdl_cred": getMdocClaims("org.iso.18013.5.1", ["given_name", "family_name"])
				// Missing portrait claim
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test("DCQL mdl-or-photoid - pass without optional address", arguments: ["dcql-mdl-or-photoid"])
	func testDcqlMdlOrPhotoIdWithoutOptionalAddress(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has mDL with identity claims but no address claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: ["mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor)],
			claimPaths: [
				"mdl_cred": getMdocClaims(
					"org.iso.18013.5.1", ["given_name", "family_name", "portrait"])
				// No address claims
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(
			result.values.first?.first?.claimQueries.count == 3, "Should have only identity claims")
	}

	@Test("DCQL claim_sets - pass with second claim set", arguments: ["dcql-claim-sets"])
	func testDcqlClaimSetsSecondSet(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has all claims from second set: last_name, postal_code, date_of_birth
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([["last_name"], ["postal_code"], ["date_of_birth"]])
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(
			result.values.first?.first?.claimQueries.count == 3,
			"Should have three claims from second set")
	}

	@Test(
		"DCQL claim_sets - pass with all claims (prefers first set)", arguments: ["dcql-claim-sets"]
	)
	func testDcqlClaimSetsAllClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has all possible claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"], ["postal_code"], ["locality"], ["region"], ["date_of_birth"],
				])
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(
			result.values.first?.first?.claimQueries.count == 4,
			"Should select first claim set with 4 claims")
		// Verify it's the first set by checking for locality/region (not postal_code)
		let paths =
			result.values.first?.first?.claimQueries.map {
				$0.path.value.map(\.claimName).joined(separator: ".")
			} ?? []
		#expect(paths.contains("locality"), "Should have locality from first set")
		#expect(paths.contains("region"), "Should have region from first set")
	}

	@Test(
		"DCQL claim_sets - fail with partial claims from both sets", arguments: ["dcql-claim-sets"])
	func testDcqlClaimSetsPartialClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has last_name and date_of_birth but missing other claims from both sets
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"],
					["date_of_birth"],
					// Missing locality, region from set 1
					// Missing postal_code from set 2
				])
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test("DCQL claim_sets - fail with wrong credential type", arguments: ["dcql-claim-sets"])
	func testDcqlClaimSetsWrongCredentialType(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has wrong credential type
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"other_cred": ("https://example.com/other", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"other_cred": getSdjwtClaims([["last_name"], ["postal_code"], ["date_of_birth"]])
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test("DCQL query values - pass with exact value matches", arguments: ["dcql-query-values"])
	func testDcqlQueryValuesExactMatch(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential with exact matching values
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"], ["first_name"], ["address", "street_address"], ["postal_code"],
				])
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Doe"],
					ClaimPath([.claim(name: "postal_code")]): ["90210"],
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result.values.first?.first?.claimQueries.count == 4, "Should have all four claims")
	}

	@Test("DCQL query values - pass with alternative postal code", arguments: ["dcql-query-values"])
	func testDcqlQueryValuesAlternativeValue(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential with second postal code option
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"], ["first_name"], ["address", "street_address"], ["postal_code"],
				])
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Doe"],
					ClaimPath([.claim(name: "postal_code")]): ["90211"],
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result.values.first?.first?.claimQueries.count == 4, "Should have all four claims")
	}

	@Test("DCQL query values - fail with wrong last name", arguments: ["dcql-query-values"])
	func testDcqlQueryValuesWrongLastName(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential but last_name doesn't match
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"], ["first_name"], ["address", "street_address"], ["postal_code"],
				])
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Smith"],  // Wrong value
					ClaimPath([.claim(name: "postal_code")]): ["90210"],
				]
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test("DCQL query values - fail with wrong postal code", arguments: ["dcql-query-values"])
	func testDcqlQueryValuesWrongPostalCode(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential but postal_code doesn't match any option
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"], ["first_name"], ["address", "street_address"], ["postal_code"],
				])
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Doe"],
					ClaimPath([.claim(name: "postal_code")]): ["90212"],  // Wrong value
				]
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test(
		"DCQL query values - fail when missing value constraint claims",
		arguments: ["dcql-query-values"])
	func testDcqlQueryValuesMissingClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential but missing postal_code claim entirely
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"],
					["first_name"],
					["address", "street_address"],
					// Missing postal_code
				])
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Doe"]
				]
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test(
		"DCQL query values - pass with multiple matching values", arguments: ["dcql-query-values"])
	func testDcqlQueryValuesMultipleMatchingValues(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential with both postal code values available
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"], ["first_name"], ["address", "street_address"], ["postal_code"],
				])
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Doe"],
					ClaimPath([.claim(name: "postal_code")]): ["90210", "90211"],  // Has both
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result.values.first?.first?.claimQueries.count == 4, "Should have all four claims")
	}

	// MARK: - Structured WalletError.Code tests

	@Test("WalletError has .claimNotFound code when claim is missing", arguments: ["dcql-vehicle"])
	func testErrorCodeClaimNotFound(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let wrapper = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcql = try DCQL(credentials: wrapper.credentials)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: ["cred1": ("org.iso.7367.1.mVRC", DocDataFormat.cbor)],
			claimPaths: [
				"cred1": [
					ClaimPath([.claim(name: "org.iso.7367.1"), .claim(name: "vehicle_holder")])
					// Missing first_name claim
				]
			]
		)
		do {
			_ = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
			Issue.record("Expected WalletError to be thrown")
		} catch let error as WalletError {
			#expect(error.code == .claimNotFound, "Error code should be .claimNotFound")
			#expect(
				error.context["claimPath"] == "org.iso.18013.5.1/first_name",
				"Context should contain the missing claim path")
		}
	}

	@Test(
		"WalletError has .credentialNotFound code when docType is missing",
		arguments: ["dcql-vehicle"])
	func testErrorCodeCredentialNotFound(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let wrapper = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcql = try DCQL(credentials: wrapper.credentials)
		// No credentials at all
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [:],
			claimPaths: [:]
		)
		do {
			_ = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
			Issue.record("Expected WalletError to be thrown")
		} catch let error as WalletError {
			#expect(error.code == .credentialNotFound, "Error code should be .credentialNotFound")
			#expect(
				error.context["docType"] == "org.iso.7367.1.mVRC",
				"Context should contain the missing docType")
		}
	}

	@Test(
		"WalletError has .claimValueMismatch code when value doesn't match",
		arguments: ["dcql-query-values"])
	func testErrorCodeClaimValueMismatch(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"], ["first_name"], ["address", "street_address"], ["postal_code"],
				])
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Smith"],  // Wrong value
					ClaimPath([.claim(name: "postal_code")]): ["90210"],
				]
			]
		)
		do {
			_ = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
			Issue.record("Expected WalletError to be thrown")
		} catch let error as WalletError {
			#expect(error.code == .claimValueMismatch, "Error code should be .claimValueMismatch")
			#expect(
				error.context["claimPath"] == "last_name",
				"Context should contain the mismatched claim path")
		}
	}

	@Test(
		"WalletError has .claimSetNotSatisfied code when no claim_set option works",
		arguments: ["dcql-claim-sets"])
	func testErrorCodeClaimSetNotSatisfied(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_cred": getSdjwtClaims([
					["last_name"],
					["date_of_birth"],
					// Missing locality, region from set 1
					// Missing postal_code from set 2
				])
			]
		)
		do {
			_ = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
			Issue.record("Expected WalletError to be thrown")
		} catch let error as WalletError {
			#expect(
				error.code == .claimSetNotSatisfied, "Error code should be .claimSetNotSatisfied")
			#expect(
				error.context["claimPath"] != nil,
				"Context should contain the first missing claim path")
		}
	}

	// MARK: - multiple flag tests

	@Test("DCQL multiple flag - returns all matching credentials")
	func testDcqlMultipleFlagReturnsAllMatches() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-multiple")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has two credentials of the same type
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_1": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				),
				"pid_2": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				),
			],
			claimPaths: [
				"pid_1": getSdjwtClaims([["given_name"], ["family_name"]]),
				"pid_2": getSdjwtClaims([["given_name"], ["family_name"]]),
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should bundle all matching credentials when multiple is true")
		let bundled = result.values.first
		#expect(bundled?.count == 2, "Should contain both matching credentials")
		#expect(
			bundled?.contains(where: { $0.credentialId == "pid_1" }) == true, "Should include pid_1"
		)
		#expect(
			bundled?.contains(where: { $0.credentialId == "pid_2" }) == true, "Should include pid_2"
		)
	}

	@Test("DCQL multiple flag - returns single credential when only one matches")
	func testDcqlMultipleFlagSingleMatch() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-multiple")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has one credential of the matching type and one of a different type
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_1": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				),
				"other": ("https://example.com/other_credential", DocDataFormat.sdjwt),
			],
			claimPaths: [
				"pid_1": getSdjwtClaims([["given_name"], ["family_name"]]),
				"other": getSdjwtClaims([["some_claim"]]),
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should return the single matching credential")
		#expect(
			result.values.first?.contains(where: { $0.credentialId == "pid_1" }) == true,
			"Should include pid_1")
	}

	@Test("DCQL multiple flag - throws when no credential satisfies claims")
	func testDcqlMultipleFlagThrowsWhenNoClaimsSatisfied() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-multiple")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential of the right type but missing required claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_1": (
					"https://credentials.example.com/identity_credential", DocDataFormat.sdjwt
				)
			],
			claimPaths: [
				"pid_1": getSdjwtClaims([
					["given_name"]
					// Missing family_name
				])
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	// MARK: - WalletError tests

	@Test("WalletError backward compatibility — code and context default to nil and empty")
	func testWalletErrorBackwardCompatibility() throws {
		let error = WalletError(description: "Some legacy error")
		#expect(error.code == nil, "Code should default to nil")
		#expect(error.context.isEmpty, "Context should default to empty")
		#expect(error.errorDescription == "Some legacy error", "Description should still work")
	}

	@Test("WalletError with code and context preserves all fields")
	func testWalletErrorStructuredFields() throws {
		let error = WalletError(
			description: "Claim not found: family_name_birth",
			code: .claimNotFound,
			context: ["claimPath": "family_name_birth"]
		)
		#expect(error.code == .claimNotFound)
		#expect(error.context["claimPath"] == "family_name_birth")
		#expect(error.errorDescription == "Claim not found: family_name_birth")
	}

	// MARK: - mdoc mDL + (PhotoID OR PID)

	@Test("mdoc mDL + (PhotoID OR PID) - pass with mDL and PhotoID")
	func testDcqlMdlPlusPhotoIdOption() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-mdl-photoid-or-pid")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"photoid_cred": ("org.iso.23220.2.photoid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"mdl_cred": getMdocClaims("org.iso.18013.5.1", ["family_name", "given_name"]),
				"photoid_cred": [
					ClaimPath([.claim(name: "org.iso.23220.photoid.1"), .claim(name: "birth_date")])
				],
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		print("Keys: \(Array(result.keys))")
		#expect(result.count == 1, "Should have one option (mdl+photoid)")
		let combo = result.values.first
		#expect(combo?.count == 2, "Should have two credentials in the combination")
		#expect(combo?.contains(where: { $0.credentialId == "mdl_cred" }) == true)
		#expect(combo?.contains(where: { $0.credentialId == "photoid_cred" }) == true)
		#expect(combo?.first(where: { $0.credentialId == "mdl_cred" })?.claimQueries.count == 2)
		#expect(combo?.first(where: { $0.credentialId == "photoid_cred" })?.claimQueries.count == 1)
	}

	@Test("mdoc mDL + (PhotoID OR PID) - pass with mDL and PID")
	func testDcqlMdlPlusPidOption() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-mdl-photoid-or-pid")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"pid_cred": ("eu.europa.ec.eudi.pid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"mdl_cred": getMdocClaims("org.iso.18013.5.1", ["family_name", "given_name"]),
				"pid_cred": [
					ClaimPath([.claim(name: "eu.europa.ec.eudi.pid.1"), .claim(name: "birth_date")])
				],
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		print("Keys: \(Array(result.keys))")
		#expect(result.count == 1, "Should have one option (mdl+pid)")
		let combo = result.values.first
		#expect(combo?.count == 2, "Should have two credentials in the combination")
		#expect(combo?.contains(where: { $0.credentialId == "mdl_cred" }) == true)
		#expect(combo?.contains(where: { $0.credentialId == "pid_cred" }) == true)
	}

	@Test("mdoc mDL + (PhotoID OR PID) - pass with all three returns two options")
	func testDcqlMdlPlusPhotoIdAndPid() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-mdl-photoid-or-pid")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"photoid_cred": ("org.iso.23220.2.photoid.1", DocDataFormat.cbor),
				"pid_cred": ("eu.europa.ec.eudi.pid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"mdl_cred": getMdocClaims("org.iso.18013.5.1", ["family_name", "given_name"]),
				"photoid_cred": [
					ClaimPath([.claim(name: "org.iso.23220.photoid.1"), .claim(name: "birth_date")])
				],
				"pid_cred": [
					ClaimPath([.claim(name: "eu.europa.ec.eudi.pid.1"), .claim(name: "birth_date")])
				],
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		print("Keys: \(Array(result.keys))")
		#expect(result.count == 2, "Should have two options (mdl+photoid and mdl+pid)")
		// Both options should include mDL
		#expect(result.values.allSatisfy { $0.contains(where: { $0.credentialId == "mdl_cred" }) })
	}

	@Test("mdoc mDL + (PhotoID OR PID) - pass with two mDLs returns two options per alternative")
	func testDcqlTwoMdlsPlusPhotoId() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-mdl-photoid-or-pid")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_1": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"mdl_2": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"photoid_cred": ("org.iso.23220.2.photoid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"mdl_1": getMdocClaims("org.iso.18013.5.1", ["family_name", "given_name"]),
				"mdl_2": getMdocClaims("org.iso.18013.5.1", ["family_name", "given_name"]),
				"photoid_cred": [
					ClaimPath([.claim(name: "org.iso.23220.photoid.1"), .claim(name: "birth_date")])
				],
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		print("Keys: \(Array(result.keys))")
		// mdl has 2 matches × photoid option = 2 combinations
		#expect(result.count == 2, "Should have two options for the two mDL alternatives")
		#expect(
			result.values.allSatisfy { $0.contains(where: { $0.credentialId == "photoid_cred" }) })
	}

	@Test("mdoc mDL + (PhotoID OR PID) - fail without mDL")
	func testDcqlMdlPlusPhotoIdOrPidFailsWithoutMdl() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-mdl-photoid-or-pid")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"photoid_cred": ("org.iso.23220.2.photoid.1", DocDataFormat.cbor),
				"pid_cred": ("eu.europa.ec.eudi.pid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"photoid_cred": [
					ClaimPath([.claim(name: "org.iso.23220.photoid.1"), .claim(name: "birth_date")])
				],
				"pid_cred": [
					ClaimPath([.claim(name: "eu.europa.ec.eudi.pid.1"), .claim(name: "birth_date")])
				],
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	// MARK: - mDL + PID required, PhotoID optional

	@Test("mDL + PID required, PhotoID optional - pass with all three")
	func testDcqlMdlPidRequiredPhotoidOptionalAllThree() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-mdl-pid-required-photoid-optional")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"pid_cred": ("eu.europa.ec.eudi.pid.1", DocDataFormat.cbor),
				"photoid_cred": ("org.iso.23220.2.photoid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"mdl_cred": getMdocClaims("org.iso.18013.5.1", ["family_name", "given_name"]),
				"pid_cred": getMdocClaims("eu.europa.ec.eudi.pid.1", ["family_name", "given_name"]),
				"photoid_cred": [ClaimPath([.claim(name: "org.iso.23220.photoid.1"), .claim(name: "birth_date")])],
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		print("Keys: \(Array(result.keys))")
		// Two options: one with required only (mdl+pid), one with required+optional (mdl+pid+photoid)
		#expect(result.count == 2)
		let withoutOptional = result.values.first(where: { $0.count == 2 })
		let withOptional = result.values.first(where: { $0.count == 3 })
		#expect(withoutOptional != nil, "Should have option with just mDL + PID")
		#expect(withOptional != nil, "Should have option with mDL + PID + PhotoID")
		#expect(withOptional?.contains(where: { $0.credentialId == "mdl_cred" }) == true)
		#expect(withOptional?.contains(where: { $0.credentialId == "pid_cred" }) == true)
		#expect(withOptional?.contains(where: { $0.credentialId == "photoid_cred" }) == true)
	}

	@Test("mDL + PID required, PhotoID optional - pass without PhotoID")
	func testDcqlMdlPidRequiredPhotoidOptionalNoPhotoid() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-mdl-pid-required-photoid-optional")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"pid_cred": ("eu.europa.ec.eudi.pid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"mdl_cred": getMdocClaims("org.iso.18013.5.1", ["family_name", "given_name"]),
				"pid_cred": getMdocClaims("eu.europa.ec.eudi.pid.1", ["family_name", "given_name"]),
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		print("Keys: \(Array(result.keys))")
		// Should still pass — PhotoID is optional
		#expect(result.count == 1)
		let combo = result.values.first
		#expect(combo?.count == 2, "Should have mDL + PID only")
		#expect(combo?.contains(where: { $0.credentialId == "mdl_cred" }) == true)
		#expect(combo?.contains(where: { $0.credentialId == "pid_cred" }) == true)
	}

	@Test("mDL + PID required, PhotoID optional - fail without mDL")
	func testDcqlMdlPidRequiredPhotoidOptionalNoMdl() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-mdl-pid-required-photoid-optional")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("eu.europa.ec.eudi.pid.1", DocDataFormat.cbor),
				"photoid_cred": ("org.iso.23220.2.photoid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"pid_cred": getMdocClaims("eu.europa.ec.eudi.pid.1", ["family_name", "given_name"]),
				"photoid_cred": [ClaimPath([.claim(name: "org.iso.23220.photoid.1"), .claim(name: "birth_date")])],
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test("mDL + PID required, PhotoID optional - two mDLs expands Cartesian")
	func testDcqlMdlPidRequiredPhotoidOptionalTwoMdls() throws {
		let dcqlData = try loadTestResource(fileName: "dcql-mdl-pid-required-photoid-optional")
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_1": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"mdl_2": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"pid_cred": ("eu.europa.ec.eudi.pid.1", DocDataFormat.cbor),
			],
			claimPaths: [
				"mdl_1": getMdocClaims("org.iso.18013.5.1", ["family_name", "given_name"]),
				"mdl_2": getMdocClaims("org.iso.18013.5.1", ["family_name", "given_name"]),
				"pid_cred": getMdocClaims("eu.europa.ec.eudi.pid.1", ["family_name", "given_name"]),
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		print("Keys: \(Array(result.keys))")
		// 2 mDLs × 1 PID = 2 combinations (no photoid available)
		#expect(result.count == 2, "Should have two options for the two mDL alternatives")
		#expect(result.values.allSatisfy { $0.contains(where: { $0.credentialId == "pid_cred" }) })
	}
}
