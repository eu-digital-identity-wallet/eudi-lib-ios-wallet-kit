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
import X509
import OpenID4VP
import StatiumSwift

public actor WrpRegistrationValidator {
	/// Trust configuration used to validate the reader/relying-party registration certificate.
	public let trustConfig: TrustConfiguration
	public let date: Date?
	public var dcqlQueryable: DefaultDcqlQueryable?
	static let logger = Logger(label: "WrpRegistrationValidator")
	static let REG_CERT_TYPE_CWT = "rc-wrp+cwt"
	public var wrpRegistration: WrpRegistrationPolicy?
	public var wrpWarnings = [PolicyViolation]()

	public init(date: Date = .now, trustConfig: TrustConfiguration, dcqlQueryable: DefaultDcqlQueryable?) {
		self.trustConfig = trustConfig
		self.date = date
		self.dcqlQueryable = dcqlQueryable
	}
	
	public func set(dcqlQueryable: DefaultDcqlQueryable?) { self.dcqlQueryable = dcqlQueryable }
	
	public func validateCertificate(wrpac: Certificate, wrprc: String, dcql: DCQL) async -> Authorization {
		do {
			guard let wrprcData = wrprc.data(using: .ascii) else { throw WalletError(description: "WRPRC cannot be decoded", code: .invalidWrprc) }
			let wrprcToken = try x5cVerifyJwtOrCwt.parse(attestData: wrprcData, format: nil)
			let wrprcPayload: Data
			switch wrprcToken {
			case .cwt(let readerAuth):
				let type = readerAuth.coseSign1.protectedHeader.type ?? readerAuth.coseSign1.unprotectedHeader?.type
				guard let type, type == Self.REG_CERT_TYPE_CWT else { throw WalletError(description: "WRPRC header type must be \(Self.REG_CERT_TYPE_CWT)", code: .invalidWrprc, context: ["type": type ?? ""]) }
				let jsonData: Data? = if let ps = readerAuth.coseSign1.payload.asString(), let jd = ps.data(using: .ascii) { jd } else if let bs = readerAuth.coseSign1.payload.asBytes() { Data(bs) } else { nil }
				guard let jsonData else { throw WalletError(description: "WRPRC cwt payload be decoded", code: .invalidWrprc) }
				wrprcPayload = jsonData
			case .jwt(let jws):
				// The JWT typ header must be rc-wrp+jwt.
				let type = jws.protectedHeader.type
				guard let type, type == OpenId4VPSpec.WRPRC_JWT_TYPE else { throw WalletError(description: "WRPRC header type must be \(OpenId4VPSpec.WRPRC_JWT_TYPE)", code: .invalidWrprc, context: ["type": jws.protectedHeader.type ?? ""]) }
				wrprcPayload = jws.payload
			}
			let wrpRegistrationPolicy = try JSONDecoder().decode(WrpRegistrationPolicy.self, from: wrprcPayload)
			wrpRegistration = wrpRegistrationPolicy
			if let exp = wrpRegistrationPolicy.exp, Date.now > Date(timeIntervalSince1970: Double(exp)) { throw WalletError(description: "WRPRC is expired", code: .invalidWrprc) }
			if !wrpRegistrationPolicy.isBound(to: wrpac) { wrpWarnings.append(.init("WRPRC not bound to requester access certificate")) } //else { throw WalletError(description: "WRPRC not bound to requester access certificate", code: .invalidWrprc) }
			guard let status = wrpRegistrationPolicy.status else { throw WalletError(description: "WRPRC missing status", code: .invalidWrprc) }
			let statusService = DocumentStatusService(statusList: status.statusList, trustConfig: trustConfig)
			let credStatus = try await statusService.getStatus()
			guard credStatus == .valid else { throw WalletError(description: "WRPRC status not valid", code: .invalidWrprc)  }
			let (isValid, reason) = try await x5cVerifyJwtOrCwt.validateTrust(wrprcToken, trustValidator: trustConfig.registrationTrustManager)
			if !isValid {
				let message = "\(wrprcToken.format.rawValue) status token trust error: \(reason ?? "")"
				switch trustConfig.wrprcTrustPolicy {
				case .warning: Self.logger.warning("\(message)"); wrpWarnings.append(.init(message))
				case .enforce: throw WalletError(description: message, code: .trustError)
				}
			}
			guard let dcqlQueryable else { throw WalletError(description: "DCQL queryable not computed", code: .internalError) }
			let options = try OpenId4VpUtils.resolveDcql(dcql, queryable: dcqlQueryable)
			var allWarnings = OpenId4VpUtils.validateDcqlPolicy(credentialSetOptions: options, policy: wrpRegistrationPolicy)
			allWarnings[""] = wrpWarnings
			return .granted(warnings: allWarnings)
		} catch {
			wrpWarnings.append(.init("WRP policy could not be created: \(error.localizedDescription)"))
			Self.logger.error("Error in validate registration certificate: \(wrprc): \(error)")
			return trustConfig.wrprcTrustPolicy == .enforce ?
				.notGranted(error: .init(error.localizedDescription)) :
				.granted(warnings: ["": [.init(error.localizedDescription)]])
	  }
	}
}
