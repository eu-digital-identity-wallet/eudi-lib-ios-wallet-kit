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
public struct WrpRegistrationPolicy: Decodable {
	public let entitlements: [String]
	public let sub: String
	public let country: String
	public let policyID: [String]
	public let credentials: [PolicyCredential]
	public let purpose: [Purpose]
	public let registryURI: String
	public let certificatePolicy: String
	public let srvDescription: [Purpose]
	public let supportURI: String
	public let supervisoryAuthority: SupervisoryAuthority
	public let privacyPolicy: String
	public let name: String
	public let infoURI: String
	public let subLn: String
	public let iat: Int
	public let status: Status

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
public struct PolicyCredential: Decodable {
	public let format: String
	public let meta: Meta
	public let claim: [PolicyClaim]

	enum CodingKeys: String, CodingKey {
		case format = "format"
		case meta = "meta"
		case claim = "claim"
	}
}

// MARK: - Claim
public struct PolicyClaim: Decodable {
	public let path: ClaimPath

	enum CodingKeys: String, CodingKey {
		case path = "path"
	}
}

// MARK: - Meta
public struct Meta: Decodable {
	public let vctValues: [String]?
	public let doctypeValue: String?

	enum CodingKeys: String, CodingKey {
		case vctValues = "vct_values"
		case doctypeValue = "doctype_value"
	}
}

// MARK: - Purpose
public struct Purpose: Decodable {
	public let lang: String
	public let value: String

	enum CodingKeys: String, CodingKey {
		case lang = "lang"
		case value = "value"
	}
}

// MARK: - SupervisoryAuthority
public struct SupervisoryAuthority: Decodable {
	public let email: String
	public let phone: String
	public let uri: String

	enum CodingKeys: String, CodingKey {
		case email = "email"
		case phone = "phone"
		case uri = "uri"
	}
}
