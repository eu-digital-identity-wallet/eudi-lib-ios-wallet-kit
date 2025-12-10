/*
 * Copyright (c) 2023 European Commission
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

import Testing
@testable import EudiWalletKit
import Foundation
import CryptoKit
import MdocDataModel18013
import WalletStorage
import SwiftCBOR
@testable import JOSESwift
import eudi_lib_sdjwt_swift
import OpenID4VP
import enum OpenID4VP.ClaimPathElement
import struct OpenID4VP.ClaimPath

struct DcqlQueryTests {

	/// Helper method to load test resources
	private func loadTestResource(fileName: String, ext: String = "json") throws -> Data {
		// Remove extension if already included in fileName
		let name = fileName.hasSuffix(".\(ext)") ? String(fileName.dropLast(ext.count + 1)) : fileName
		guard let data = Data(name: name, ext: ext, from: Bundle.module) else {
			throw NSError(domain: "TestError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Resource file not found: \(name).\(ext)"])
		}
		return data
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
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "first_name")])
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential query result")
		#expect(result["cred1"]?.count == 2, "Should have both claim paths for cred1")
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

	@Test("DCQL multiple pid with credential_sets - pass with first option", arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsFirstOption(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has the "pid" credential that satisfies the first option of the first credential_set
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "given_name")]),
					ClaimPath([.claim(name: "family_name")]),
					ClaimPath([.claim(name: "address"), .claim(name: "street_address")])
				]
			]
		)

		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["pid_cred"]?.count == 3, "Should have all three claims for pid")
	}

	@Test("DCQL multiple credentials with credential_sets - pass with third option (multiple creds)", arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsThirdOption(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has both reduced credentials (third option of first credential_set)
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"reduced_id": ("https://credentials.example.com/reduced_identity_credential", DocDataFormat.sdjwt),
				"residence": ("https://cred.example/residence_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"reduced_id": [
					ClaimPath([.claim(name: "given_name")]),
					ClaimPath([.claim(name: "family_name")])
				],
				"residence": [
					ClaimPath([.claim(name: "postal_code")]),
					ClaimPath([.claim(name: "locality")]),
					ClaimPath([.claim(name: "region")])
				]
			]
		)

		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 2, "Should have two credentials")
		#expect(result["reduced_id"]?.count == 2, "Should have two claims for reduced_id")
		#expect(result["residence"]?.count == 3, "Should have three claims for residence")
	}

	@Test("DCQL multiple credentials with credential_sets - pass with optional credential", arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsWithOptional(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has "pid" and optional "nice_to_have" credential
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt),
				"rewards": ("https://company.example/company_rewards", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "given_name")]),
					ClaimPath([.claim(name: "family_name")]),
					ClaimPath([.claim(name: "address"), .claim(name: "street_address")])
				],
				"rewards": [
					ClaimPath([.claim(name: "rewards_number")])
				]
			]
		)

		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 2, "Should have two credentials including optional")
		#expect(result["pid_cred"] != nil, "Should have pid credential")
		#expect(result["rewards"] != nil, "Should have optional rewards credential")
		#expect(result["pid_cred"]?.count == 3, "Should have three claims for pid_cred")
		#expect(result["rewards"]?.count == 1, "Should have one claim for rewards")
	}


	@Test("DCQL multiple credentials with credential_sets - fail when required set not satisfied", arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsFailRequired(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet only has the optional credential, not any required ones
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"rewards": ("https://company.example/company_rewards", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"rewards": [
					ClaimPath([.claim(name: "rewards_number")])
				]
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test("DCQL multiple credentials with credential_sets - fail when partial claims", arguments: ["dcql-pid-multiple"])
	func testDcqlMultipleCredentialsFailPartialClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has "pid" credential but missing one required claim
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "given_name")]),
					ClaimPath([.claim(name: "family_name")])
					// Missing address.street_address claim
				]
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
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor)
			],
			claimPaths: [
				"mdl_cred": [
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "given_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "family_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "portrait")])
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["mdl_cred"]?.count == 3, "Should have three identity claims")
	}

	@Test("DCQL mdl-or-photoid - pass with photo card", arguments: ["dcql-mdl-or-photoid"])
	func testDcqlMdlOrPhotoIdWithPhotoCard(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has photo ID card with identity claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"photo_cred": ("org.iso.23220.photoid.1", DocDataFormat.cbor)
			],
			claimPaths: [
				"photo_cred": [
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "given_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "family_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "portrait")])
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["photo_cred"]?.count == 3, "Should have three identity claims")
	}

	@Test("DCQL mdl-or-photoid - pass with photo card and address", arguments: ["dcql-mdl-or-photoid"])
	func testDcqlMdlOrPhotoIdWithPhotoCardAndAddress(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has photo card with both identity and address claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"photo_cred": ("org.iso.23220.photoid.1", DocDataFormat.cbor)
			],
			claimPaths: [
				"photo_cred": [
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "given_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "family_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "portrait")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "resident_address")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "resident_country")])
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["photo_cred"]?.count == 5, "Should have identity and address claims")
	}

	@Test("DCQL mdl-or-photoid - pass with both mDL and photo card prefers first", arguments: ["dcql-mdl-or-photoid"])
	func testDcqlMdlOrPhotoIdWithBoth(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has both mDL and photo card
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor),
				"photo_cred": ("org.iso.23220.photoid.1", DocDataFormat.cbor)
			],
			claimPaths: [
				"mdl_cred": [
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "given_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "family_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "portrait")])
				],
				"photo_cred": [
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "given_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "family_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "portrait")])
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential (first option)")
		#expect(result["mdl_cred"] != nil, "Should prefer mDL as first option")
	}


	@Test("DCQL mdl-or-photoid - fail with partial identity claims", arguments: ["dcql-mdl-or-photoid"])
	func testDcqlMdlOrPhotoIdFailPartialClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has mDL but missing required claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor)
			],
			claimPaths: [
				"mdl_cred": [
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "given_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "family_name")])
					// Missing portrait claim
				]
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
			credentials: [
				"mdl_cred": ("org.iso.18013.5.1.mDL", DocDataFormat.cbor)
			],
			claimPaths: [
				"mdl_cred": [
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "given_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "family_name")]),
					ClaimPath([.claim(name: "org.iso.18013.5.1"), .claim(name: "portrait")])
					// No address claims
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["mdl_cred"]?.count == 3, "Should have only identity claims")
	}

	@Test("DCQL claim_sets - pass with second claim set", arguments: ["dcql-claim-sets"])
	func testDcqlClaimSetsSecondSet(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has all claims from second set: last_name, postal_code, date_of_birth
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "postal_code")]),
					ClaimPath([.claim(name: "date_of_birth")])
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["pid_cred"]?.count == 3, "Should have three claims from second set")
	}

	@Test("DCQL claim_sets - pass with all claims (prefers first set)", arguments: ["dcql-claim-sets"])
	func testDcqlClaimSetsAllClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has all possible claims
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "postal_code")]),
					ClaimPath([.claim(name: "locality")]),
					ClaimPath([.claim(name: "region")]),
					ClaimPath([.claim(name: "date_of_birth")])
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["pid_cred"]?.count == 4, "Should select first claim set with 4 claims")
		// Verify it's the first set by checking for locality/region (not postal_code)
		let paths = result["pid_cred"]?.map { $0.path.value.map(\.claimName).joined(separator: ".") } ?? []
		#expect(paths.contains("locality"), "Should have locality from first set")
		#expect(paths.contains("region"), "Should have region from first set")
	}

	@Test("DCQL claim_sets - fail with partial claims from both sets", arguments: ["dcql-claim-sets"])
	func testDcqlClaimSetsPartialClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has last_name and date_of_birth but missing other claims from both sets
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "date_of_birth")])
					// Missing locality, region from set 1
					// Missing postal_code from set 2
				]
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
				"other_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "postal_code")]),
					ClaimPath([.claim(name: "date_of_birth")])
				]
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
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "first_name")]),
					ClaimPath([.claim(name: "address"), .claim(name: "street_address")]),
					ClaimPath([.claim(name: "postal_code")])
				]
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Doe"],
					ClaimPath([.claim(name: "postal_code")]): ["90210"]
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["pid_cred"]?.count == 4, "Should have all four claims")
	}

	@Test("DCQL query values - pass with alternative postal code", arguments: ["dcql-query-values"])
	func testDcqlQueryValuesAlternativeValue(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential with second postal code option
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "first_name")]),
					ClaimPath([.claim(name: "address"), .claim(name: "street_address")]),
					ClaimPath([.claim(name: "postal_code")])
				]
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Doe"],
					ClaimPath([.claim(name: "postal_code")]): ["90211"]
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["pid_cred"]?.count == 4, "Should have all four claims")
	}

	@Test("DCQL query values - fail with wrong last name", arguments: ["dcql-query-values"])
	func testDcqlQueryValuesWrongLastName(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential but last_name doesn't match
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "first_name")]),
					ClaimPath([.claim(name: "address"), .claim(name: "street_address")]),
					ClaimPath([.claim(name: "postal_code")])
				]
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Smith"],  // Wrong value
					ClaimPath([.claim(name: "postal_code")]): ["90210"]
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
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "first_name")]),
					ClaimPath([.claim(name: "address"), .claim(name: "street_address")]),
					ClaimPath([.claim(name: "postal_code")])
				]
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Doe"],
					ClaimPath([.claim(name: "postal_code")]): ["90212"]  // Wrong value
				]
			]
		)
		#expect(throws: WalletError.self) {
			try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		}
	}

	@Test("DCQL query values - fail when missing value constraint claims", arguments: ["dcql-query-values"])
	func testDcqlQueryValuesMissingClaims(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential but missing postal_code claim entirely
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "first_name")]),
					ClaimPath([.claim(name: "address"), .claim(name: "street_address")])
					// Missing postal_code
				]
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

	@Test("DCQL query values - pass with multiple matching values", arguments: ["dcql-query-values"])
	func testDcqlQueryValuesMultipleMatchingValues(dcqlFile: String) throws {
		let dcqlData = try loadTestResource(fileName: dcqlFile)
		let dcql = try JSONDecoder().decode(DCQL.self, from: dcqlData)
		// Wallet has credential with both postal code values available
		let dcqlQueryable = DefaultDcqlQueryable(
			credentials: [
				"pid_cred": ("https://credentials.example.com/identity_credential", DocDataFormat.sdjwt)
			],
			claimPaths: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]),
					ClaimPath([.claim(name: "first_name")]),
					ClaimPath([.claim(name: "address"), .claim(name: "street_address")]),
					ClaimPath([.claim(name: "postal_code")])
				]
			],
			claimValues: [
				"pid_cred": [
					ClaimPath([.claim(name: "last_name")]): ["Doe"],
					ClaimPath([.claim(name: "postal_code")]): ["90210", "90211"]  // Has both
				]
			]
		)
		let result = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
		#expect(result.count == 1, "Should have one credential")
		#expect(result["pid_cred"]?.count == 4, "Should have all four claims")
	}

}



