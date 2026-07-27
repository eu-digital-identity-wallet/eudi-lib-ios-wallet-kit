/*
 Copyright (c) 2026 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import Foundation
import struct OpenID4VP.ClaimPath
import struct MdocDataModel18013.Status

// MARK: - WRPRegistrationPolicy
struct WRPRegistrationPolicy: Decodable {
	let entitlements: [String]
	let sub: String
	let country: String
	let policyID: [String]
	let credentials: [PolicyCredential]
	let purpose: [Purpose]
	let registryURI: String
	let certificatePolicy: String
	let srvDescription: [Purpose]
	let supportURI: String
	let supervisoryAuthority: SupervisoryAuthority
	let privacyPolicy: String
	let name: String
	let infoURI: String
	let subLn: String
	let iat: Int
	let status: Status

	enum CodingKeys: String, CodingKey {
		case entitlements = "entitlements"
		case sub = "sub"
		case country = "country"
		case policyID = "policy_id"
		case credentials = "credentials"
		case purpose = "purpose"
		case registryURI = "registry_uri"
		case certificatePolicy = "certificate_policy"
		case srvDescription = "srv_description"
		case supportURI = "support_uri"
		case supervisoryAuthority = "supervisory_authority"
		case privacyPolicy = "privacy_policy"
		case name = "name"
		case infoURI = "info_uri"
		case subLn = "sub_ln"
		case iat = "iat"
		case status = "status"
	}
}

// MARK: - Credential
struct PolicyCredential: Decodable {
	let format: String
	let meta: Meta
	let claim: [PolicyClaim]

	enum CodingKeys: String, CodingKey {
		case format = "format"
		case meta = "meta"
		case claim = "claim"
	}
}

// MARK: - Claim
struct PolicyClaim: Decodable {
	let path: ClaimPath

	enum CodingKeys: String, CodingKey {
		case path = "path"
	}
}

// MARK: - Meta
struct Meta: Decodable {
	let vctValues: [String]?
	let doctypeValue: String?

	enum CodingKeys: String, CodingKey {
		case vctValues = "vct_values"
		case doctypeValue = "doctype_value"
	}
}

// MARK: - Purpose
struct Purpose: Decodable {
	let lang: String
	let value: String

	enum CodingKeys: String, CodingKey {
		case lang = "lang"
		case value = "value"
	}
}

// MARK: - SupervisoryAuthority
struct SupervisoryAuthority: Decodable {
	let email: String
	let phone: String
	let uri: String

	enum CodingKeys: String, CodingKey {
		case email = "email"
		case phone = "phone"
		case uri = "uri"
	}
}
