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
import MdocDataModel18013
import MdocSecurity18013
import Security
import StatiumSwift
import SwiftCBOR
import JSONWebSignature
import Logging
import OrderedCollections
import X509
import OpenID4VP
import StatiumSwift
import struct OpenID4VP.OpenId4VPSpec

/// Validates the WRP registration certificate (WRPRC) of a verifier (relying party) during presentation.
public actor WrpVpRegistrationValidator {
	/// Trust configuration used to validate the reader/relying-party registration certificate.
	public let trustConfig: TrustConfiguration
	public let date: Date?
	public var dcqlQueryable: DefaultDcqlQueryable?
	static let logger = Logger(label: "WrpRegistrationValidator")
	/// Label of the `ItemsRequest.requestInfo` member carrying the WRPRC in ISO/IEC 18013-5 requests (ETSI TS 119 472-2)
	static let REG_CERT_REQUEST_INFO_KEY = "euWrprc"
	/// The registration policy decoded from the WRPRC by the last `validateCertificate` call, if any.
	public var wrpVpRegistrationPolicy: WrpRegistrationPolicy?
	/// Warnings collected during validation, keyed by credential query identifier; the empty key holds request-wide warnings.
	public var wrpVpWarnings = [String:[PolicyViolation]]()

	public init(date: Date = .now, trustConfig: TrustConfiguration, dcqlQueryable: DefaultDcqlQueryable? = nil) {
		self.trustConfig = trustConfig
		self.date = date
		self.dcqlQueryable = dcqlQueryable
	}
	
	public func set(dcqlQueryable: DefaultDcqlQueryable?) { self.dcqlQueryable = dcqlQueryable }
	
	public func validateCertificate(wrpac: Certificate, wrprc: String, dcql: DCQL) async -> Authorization {
		guard let wrprcData = wrprc.data(using: .ascii) else {
			wrpVpWarnings["", default: []].append(.init("WRPRC cannot be decoded"))
			return trustConfig.wrprcTrustPolicy == .enforce ?
				.notGranted(error: .init("WRPRC cannot be decoded")) :
				.granted(warnings: wrpVpWarnings)
		}
		return await validateCertificate(wrpac: wrpac, wrprcData: wrprcData, dcql: dcql)
	}

	/// Validate the relying party registration certificate (WRPRC) carried in an ISO/IEC 18013-5 device request.
	///
	/// According to ETSI TS 119 472-2 (proximity profile), the WRPRC is repeated in the `requestInfo`
	/// member of each `ItemsRequest`, under the "euWrprc" label, as a CBOR byte string containing
	/// the serialization of the registration certificate (JWT or CWT).
	/// - Parameters:
	///   - wrpac: The relying party access certificate (reader authentication leaf certificate), if available
	///   - deviceRequest: The decoded device request received from the verifier
	///   - dcql: A DCQL query equivalent to the requested items, used to validate the request scope against the registration policy
	/// - Returns: The authorization result, or `nil` when the request carries no registration certificate
	public func validateDeviceRequestCertificate(wrpac: Certificate?, deviceRequest: DeviceRequest, dcql: DCQL) async -> Authorization? {
		var wrprcValues = [Data]()
		for docR in deviceRequest.docRequests {
			guard let extValue = docR.itemsRequest.requestInfo?.extensions?[Self.REG_CERT_REQUEST_INFO_KEY],
				case let .byteString(bs) = extValue else { continue }
			wrprcValues.append(Data(bs))
		}
		guard let wrprcData = wrprcValues.first else { return nil }
		if wrprcValues.count < deviceRequest.docRequests.count { wrpVpWarnings["", default: []].append(.init("WRPRC not repeated in every ItemsRequest.requestInfo")) }
		if wrprcValues.dropFirst().contains(where: { $0 != wrprcData }) { wrpVpWarnings["", default: []].append(.init("Different WRPRC values found in ItemsRequest.requestInfo")) }
		return await validateCertificate(wrpac: wrpac, wrprcData: wrprcData, dcql: dcql)
	}

	/// Validate the relying party registration certificate and check the requested items against the registration policy.
	/// - Parameters:
	///   - wrpac: The relying party access certificate (reader authentication leaf certificate), if available
	///   - wrprcData: The raw WRPRC token bytes (JWT or CWT serialization)
	///   - dcql: A DCQL query equivalent to the requested items, used to validate the request scope against the registration policy
	/// - Returns: The authorization result; warnings are keyed by credential query identifier,
	///   with the empty key used for request-wide warnings
	public func validateCertificate(wrpac: Certificate?, wrprcData: Data, dcql: DCQL) async -> Authorization {
		do {
			let (policy, warns) = try await WrpVciRegistrationValidator.validateWrprcCore(trustConfig, wrpac: wrpac, wrprcData: wrprcData)
			wrpVpRegistrationPolicy = policy
			wrpVpWarnings[""] = warns.map(PolicyViolation.init) 
			guard let dcqlQueryable else { throw WalletError(description: "DCQL queryable not computed", code: .internalError) }
			let options = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
			OpenId4VpUtils.validateDcqlPolicy(credentialSetOptions: options, policy: policy, wrpVpWarnings: &wrpVpWarnings)
			return .granted(warnings: wrpVpWarnings)
		} catch {
			wrpVpWarnings["", default: []].append(.init("WRP policy could not be created: \(error.localizedDescription)"))
			Self.logger.error("Error in validate registration certificate: \(error)")
			return trustConfig.wrprcTrustPolicy == .enforce ?
				.notGranted(error: .init(error.localizedDescription)) :
				.granted(warnings: ["": [.init(error.localizedDescription)]])
	  }
	}
}
