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
import MdocSecurity18013
import X509
import OpenID4VCI
import Logging
import struct OpenID4VCI.PolicyViolation

public actor WrpVciRegistrationValidator {
	/// Trust configuration used to validate the reader/relying-party registration certificate.
	public let trustConfig: TrustConfiguration
	public let date: Date?
	static let logger = Logger(label: "WrpRegistrationValidator")
	public var wrpVciRegistrationPolicy: WrpRegistrationPolicy?
	public var wrpVciWarnings = [String:[PolicyViolation]]()
	
	public init(date: Date = .now, trustConfig: TrustConfiguration) {
		self.trustConfig = trustConfig
		self.date = date
	}
	/// Validate the WRP registration certificate (WRPRC) delivered in the issuer metadata
	/// `issuer_info` during OpenID4VCI issuance.
	///
	/// Intended to back the `OpenId4VCIConfig.registrationCertificatePolicy` closure of the
	/// OpenID4VCI library, which supplies the WRPAC and WRPRC as opaque strings.
	/// - Parameters:
	///   - wrpac: The WRP access certificate that signed the issuer metadata (base64 DER, single X.509 leaf)
	///   - wrprc: The raw WRPRC value as delivered in `issuer_info` (typically a compact-serialized JWT)
	///   - offeredConfigurations: The credential configurations referenced by the resolved credential offer
	/// - Returns: The authorization result; warnings are keyed by credential configuration identifier,
	///   with "global" used for request-wide warnings
	public func validateCertificate(wrpac: String, wrprc: String, offeredConfigurations: [CredentialConfigurationIdentifier: CredentialSupported]) async -> Authorization {
		do {
			let wrpacCertificate: Certificate?
			if let wrpacDer = Data(base64Encoded: wrpac), let certificate = try? Certificate(derEncoded: Array(wrpacDer)) {
				wrpacCertificate = certificate
			} else {
				wrpacCertificate = nil
				wrpVciWarnings["", default: []].append(.init("WRPAC cannot be decoded"))
			}
			let wrprcData = wrprc.data(using: .ascii) ?? Data(base64Encoded: wrprc)
			guard let wrprcData else { throw WalletError(description: "WRPRC cannot be decoded", code: .invalidWrprc) }
			let (policy, w) = try await Self.validateWrprcCore(trustConfig, wrpac: wrpacCertificate, wrprcData: wrprcData)
			wrpVciRegistrationPolicy = policy
			wrpVciWarnings = w.mapValues { $0.map(PolicyViolation.init) }
			Self.validateOfferedConfigurations(offeredConfigurations, policy: policy, wrpWarnings: &wrpVciWarnings)
			return .granted(warnings: wrpVciWarnings)
		} catch {
			wrpVciWarnings["", default: []].append(.init("WRP policy could not be created: \(error.localizedDescription)"))
			Self.logger.error("Error in validate registration certificate: \(error)")
			return trustConfig.wrprcTrustPolicy == .enforce ?
				.notGranted(error: PolicyViolation(error.localizedDescription)) :
				.granted(warnings: ["": [PolicyViolation(error.localizedDescription)]])
		}
	}

	/// Check each offered credential configuration against the attestations the issuer is
	/// registered to provide (`provides_attestations` claim of the WRPRC).
	/// - Returns: Warnings keyed by credential configuration identifier for uncovered configurations
	static func validateOfferedConfigurations(_ offeredConfigurations: [CredentialConfigurationIdentifier: CredentialSupported], policy: WrpRegistrationPolicy, wrpWarnings: inout [String: [PolicyViolation]]) {
		guard let providedAttestations = policy.providesAttestations else { return }
		for (identifier, supported) in offeredConfigurations {
			let isCovered: Bool = switch supported {
			case .msoMdoc(let msoMdoc): providedAttestations.contains { $0.meta.doctypeValue == msoMdoc.docType }
			case .sdJwtVc(let sdJwtVc): providedAttestations.contains { attestation in
				if let vct = sdJwtVc.vct { attestation.meta.vctValues?.contains(vct) ?? false } else { false } }
			default: true
			}
			if !isCovered {
				wrpWarnings[identifier.value, default: []].append(PolicyViolation("Credential configuration \(identifier.value) is not covered by the issuer registration certificate"))
			}
		}
	}
}

extension WrpVciRegistrationValidator {
	
	/// Core WRPRC token validation shared by the presentation (DCQL) and issuance (OpenID4VCI) flows.
	/// Parses the token, checks its type header, decodes the registration policy, and validates
	/// expiration, access-certificate binding, status and trust chain.
	/// - Returns: The decoded registration policy; soft failures are appended to ``wrpWarnings``.
	static func validateWrprcCore(_ trustConfig: TrustConfiguration, wrpac: Certificate?, wrprcData: Data) async throws -> (WrpRegistrationPolicy, [String: [String]]) {
		var wrpWarnings = [String: [String]]()
		let wrprcToken = try x5cVerifyJwtOrCwt.parse(attestData: wrprcData, format: nil)
		let wrprcPayload: Data
		switch wrprcToken {
		case .cwt(let readerAuth):
			let type = readerAuth.coseSign1.protectedHeader.type ?? readerAuth.coseSign1.unprotectedHeader?.type
			guard let type, type == REG_CERT_TYPE_CWT else { throw WalletError(description: "WRPRC header type must be \(REG_CERT_TYPE_CWT)", code: .wrprcInvalidType, context: ["type": type ?? ""]) }
			let jsonData: Data? = if let ps = readerAuth.coseSign1.payload.asString(), let jd = ps.data(using: .ascii) { jd } else if let bs = readerAuth.coseSign1.payload.asBytes() { Data(bs) } else { nil }
			guard let jsonData else { throw WalletError(description: "WRPRC cwt payload cannot be decoded", code: .wrprcPayloadDecodingFailed) }
			wrprcPayload = jsonData
		case .jwt(let jws):
			// The JWT typ header must be rc-wrp+jwt.
			let type = jws.protectedHeader.type
			guard let type, type == WRPRC_JWT_TYPE else { throw WalletError(description: "WRPRC header type must be \(WRPRC_JWT_TYPE)", code: .wrprcInvalidType, context: ["type": jws.protectedHeader.type ?? ""]) }
			wrprcPayload = jws.payload
		}
		let wrpRegistrationPolicy = try JSONDecoder().decode(WrpRegistrationPolicy.self, from: wrprcPayload)
		if let exp = wrpRegistrationPolicy.exp, Date.now > Date(timeIntervalSince1970: Double(exp)) { throw WalletError(description: "WRPRC is expired", code: .wrprcExpired) }
		if let wrpac {
			if !wrpRegistrationPolicy.isBound(to: wrpac) { wrpWarnings["", default: []].append(.init("WRPRC not bound to requester access certificate")) }
		} else {
			wrpWarnings["", default: []].append(.init("Requester access certificate not available to check WRPRC binding"))
		}
		guard let status = wrpRegistrationPolicy.status else { throw WalletError(description: "WRPRC does not have status list", code: .wrprcMissingStatus) }
		let statusService = DocumentStatusService(statusList: status.statusList, trustConfig: trustConfig)
		let credStatus = try? await statusService.getStatus()
		if let credStatus {
			if credStatus != .valid { throw WalletError(description: "WRPRC status not valid", code: .wrprcStatusInvalid, context: ["status": credStatus == .invalid ? "Invalid" : credStatus == .suspended ? "suspended" : "\(credStatus)"]) }
		} else {
			Self.logger.warning("WRPRC status list could not be retrieved")
			wrpWarnings["", default: []].append(.init("WRPRC status list could not be retrieved"))
		}
		#if canImport(EudiEtsi1196x2)
		let (isValid, reason) = try await x5cVerifyJwtOrCwt.validateTrust(wrprcToken, trustValidator: trustConfig.registrationTrustManager)
		if !isValid {
			let message = "\(wrprcToken.format.rawValue) status token trust error: \(reason ?? "")"
			switch trustConfig.wrprcTrustPolicy {
			case .warning: Self.logger.warning("\(message)"); wrpWarnings["", default: []].append(.init(message))
			case .enforce: throw WalletError(description: message, code: .wrprcTrustError)
			}
		}
		#endif
		return (wrpRegistrationPolicy, wrpWarnings)
	}
}