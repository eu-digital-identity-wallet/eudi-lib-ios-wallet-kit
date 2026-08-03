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

public struct WrpRegistrationPolicy: Decodable, Sendable {
	public let entitlements: [String]?
	public let sub: String
	public let country: String?
	public let policyID: [String]?
	public let credentials: [PolicyCredential]?
	public let purpose: [PolicyPurpose]?
	public let registryURI: String?
	public let certificatePolicy: String?
	public let srvDescription: [PolicyPurpose]?
	public let supportURI: String?
	public let supervisoryAuthority: SupervisoryAuthority?
	public let privacyPolicy: String?
	public let name: String?
	public let infoURI: String?
	public let subLn: String?
	public let subGn: String?
	public let subFn: String?
	public let iat: Int?
	public let exp: Int?
	public let status: Status?
	public let intendedUseID: String?
	public let providesAttestations: [PolicyCredential]?
	public let intermediary: PolicyIntermediary?
	/// Identifiers of the registered relying party, derived from the `sub` claim.
	public var identifiers: [RegistrationIdentifier] {
		[RegistrationIdentifier(value: sub)] 
	}

	public init(entitlements: [String]? = nil, sub: String, country: String? = nil, policyID: [String]? = nil, credentials: [PolicyCredential], purpose: [PolicyPurpose]? = nil, registryURI: String? = nil, certificatePolicy: String? = nil, srvDescription: [PolicyPurpose]? = nil, supportURI: String? = nil, supervisoryAuthority: SupervisoryAuthority? = nil, privacyPolicy: String? = nil, name: String? = nil, infoURI: String? = nil, subLn: String? = nil, subGn: String? = nil, subFn: String? = nil, iat: Int? = nil, exp: Int? = nil, status: Status? = nil, intendedUseID: String? = nil, providesAttestations: [PolicyCredential]? = nil, intermediary: PolicyIntermediary? = nil) {
		self.entitlements = entitlements
		self.sub = sub
		self.country = country
		self.policyID = policyID
		self.credentials = credentials
		self.purpose = purpose
		self.registryURI = registryURI
		self.certificatePolicy = certificatePolicy
		self.srvDescription = srvDescription
		self.supportURI = supportURI
		self.supervisoryAuthority = supervisoryAuthority
		self.privacyPolicy = privacyPolicy
		self.name = name
		self.infoURI = infoURI
		self.subLn = subLn
		self.subGn = subGn
		self.subFn = subFn
		self.iat = iat
		self.exp = exp
		self.status = status
		self.intendedUseID = intendedUseID
		self.providesAttestations = providesAttestations
		self.intermediary = intermediary
	}

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
		case subGn = "sub_gn"
		case subFn = "sub_fn"
		case iat = "iat"
		case exp = "exp"
		case status = "status"
		case intendedUseID = "intended_use_id"
		case providesAttestations = "provides_attestations"
		case intermediary = "intermediary"
	}
}

public struct PolicyIntermediary: Decodable, Sendable {
	public let identifier: String?
	// The intermediary common name is carried in the `sname` claim, not `name`.
	public let name: String?

	public init(identifier: String? = nil, name: String? = nil) {
		self.identifier = identifier
		self.name = name
	}

	enum CodingKeys: String, CodingKey {
		case identifier = "sub"
		case name = "sname"
	}
}

public struct RegistrationIdentifier: Decodable, Sendable {
	public let value: String

	public init(value: String) {
		self.value = value
	}
}

public struct PolicyCredential: Decodable, Sendable {
	public let format: String
	public let meta: PolicyCredentialMeta
	public let claims: [PolicyClaim]?

	public init(format: String, meta: PolicyCredentialMeta, claim: [PolicyClaim]?) {
		self.format = format
		self.meta = meta
		self.claims = claim
	}

	enum CodingKeys: String, CodingKey {
		case format = "format"
		case meta = "meta"
		case claims = "claim"
	}
}

public struct PolicyClaim: Decodable, Sendable {
	public let path: ClaimPath

	public init(path: ClaimPath) {
		self.path = path
	}

	enum CodingKeys: String, CodingKey {
		case path = "path"
	}
}

public struct PolicyCredentialMeta: Decodable, Sendable {
	public let vctValues: [String]?
	public let doctypeValue: String?

	public init(vctValues: [String]? = nil, doctypeValue: String? = nil) {
		self.vctValues = vctValues
		self.doctypeValue = doctypeValue
	}

	enum CodingKeys: String, CodingKey {
		case vctValues = "vct_values"
		case doctypeValue = "doctype_value"
	}
}

public struct PolicyPurpose: Decodable, Sendable {
	public let lang: String
	public let value: String

	public init(lang: String, value: String) {
		self.lang = lang
		self.value = value
	}

	enum CodingKeys: String, CodingKey {
		case lang = "lang"
		case value = "value"
	}
}

public struct SupervisoryAuthority: Decodable, Sendable {
	public let name: String?
	public let email: String?
	public let phone: String?
	public let uri: String?

	public init(name: String? = nil, email: String? = nil, phone: String? = nil, uri: String? = nil) {
		self.name = name
		self.email = email
		self.phone = phone
		self.uri = uri
	}

	enum CodingKeys: String, CodingKey {
		case name = "name"
		case email = "email"
		case phone = "phone"
		case uri = "uri"
	}
}
