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

/// Validates the WRP registration certificate (WRPRC) of a credential issuer during OpenID4VCI issuance.
public actor WrpVciRegistrationValidator {
	/// Trust configuration used to validate the issuer registration certificate.
	public let trustConfig: TrustConfiguration
	public let date: Date?
	static let logger = Logger(label: "WrpRegistrationValidator")
	/// The registration policy decoded from the WRPRC by the last ``validateCertificate(wrpac:wrprc:offeredConfigurations:)`` call, if any.
	/// Preserved even when validation fails (expiry, revocation, trust error) so the decoded identity can be inspected.
	public var wrpVciRegistrationPolicy: WrpRegistrationPolicy?
	/// Typed violations collected during validation, keyed by credential configuration identifier; the empty key holds request-wide violations.
	public var wrpVciWarnings = [String: [RegistrationPolicyViolation]]()
	
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
	///   with the empty key used for request-wide warnings
	public func validateCertificate(wrpac: String, wrprc: String, offeredConfigurations: [CredentialConfigurationIdentifier: CredentialSupported]) async -> Authorization {
		do {
			let wrpacCertificate: Certificate?
			if let wrpacDer = Data(base64Encoded: wrpac), let certificate = try? Certificate(derEncoded: Array(wrpacDer)) {
				wrpacCertificate = certificate
			} else {
				wrpacCertificate = nil
				wrpVciWarnings["", default: []].append(RegistrationPolicyViolation(reason: .wrpacDecodingFailed, message: "WRPAC cannot be decoded"))
			}
			let wrprcData = Data(base64Encoded: wrprc) ?? wrprc.data(using: .ascii)
			guard let wrprcData else { throw WalletError(description: "WRPRC cannot be decoded", code: .invalidWrprc) }
			wrpVciRegistrationPolicy = try? Self.decodeWrprc(wrprcData)
			let (policy, warns) = try await Self.validateWrprcCore(trustConfig, wrpac: wrpacCertificate, wrprcData: wrprcData)
			wrpVciRegistrationPolicy = policy
			wrpVciWarnings[""] = warns
			Self.validateOfferedConfigurations(offeredConfigurations, policy: policy, wrpVciWarnings: &wrpVciWarnings)
			let policyViolationWarnings = wrpVciWarnings.mapValues { $0.map { PolicyViolation($0.message) } }
			// Under .enforce, hard failures block issuance.
			if trustConfig.wrprcVciTrustPolicy == .enforce,
			   let enforceable = wrpVciWarnings[""]?.first(where: { Self.enforceableReasons.contains($0.reason) }) {
				return .notGranted(error: PolicyViolation(enforceable.message))
			}
			return .granted(warnings: policyViolationWarnings)
		} catch {
			let reason: RegistrationFailureReason = .wrpacDecodingFailed
			let violation = RegistrationPolicyViolation(reason: reason, message: error.localizedDescription)
			wrpVciWarnings["", default: []].append(violation)
			Self.logger.error("Error in validate registration certificate: \(error)")
			let policyViolation = PolicyViolation(error.localizedDescription)
			return trustConfig.wrprcVciTrustPolicy == .enforce ?
				.notGranted(error: policyViolation) :
				.granted(warnings: ["": [policyViolation]])
		}
	}

	/// Reasons that cause `.notGranted` when `wrprcTrustPolicy == .enforce`.
	private static let enforceableReasons: Set<RegistrationFailureReason> = [
		.expired, .statusRevoked, .statusSuspended, .statusApplicationSpecific, .statusMissing, .trustError, .invalidType
	]

	/// Check each offered credential configuration against the attestations the issuer is
	/// registered to provide (`provides_attestations` claim of the WRPRC).
	/// Warnings for uncovered configurations are appended to `wrpVciWarnings`, keyed by credential configuration identifier.
	static func validateOfferedConfigurations(_ offeredConfigurations: [CredentialConfigurationIdentifier: CredentialSupported], policy: WrpRegistrationPolicy, wrpVciWarnings: inout [String: [RegistrationPolicyViolation]]) {
		guard let providedAttestations = policy.providesAttestations else { return }
		for (identifier, supported) in offeredConfigurations {
			let isCovered: Bool = switch supported {
			case .msoMdoc(let msoMdoc): providedAttestations.contains { $0.meta.doctypeValue == msoMdoc.docType }
			case .sdJwtVc(let sdJwtVc): providedAttestations.contains { attestation in
				if let vct = sdJwtVc.vct { attestation.meta.vctValues?.contains(vct) ?? false } else { false } }
			default: true
			}
			if !isCovered {
				wrpVciWarnings[identifier.value, default: []].append(RegistrationPolicyViolation(reason: .credentialsNotCovered(credentialIds: [identifier.value]), message: "Credential configuration \(identifier.value) is not covered by the issuer registration certificate"))
			}
		}
	}
}

extension WrpVciRegistrationValidator {
	
	/// Decode the WRPRC token payload into a ``WrpRegistrationPolicy`` without performing any validation.
	/// Used to preserve the decoded identity even when subsequent validation fails.
	static func decodeWrprc(_ wrprcData: Data) throws -> WrpRegistrationPolicy {
		let wrprcToken = try x5cVerifyJwtOrCwt.parse(attestData: wrprcData, format: nil)
		let wrprcPayload: Data
		switch wrprcToken {
		case .cwt(let readerAuth):
			let jsonData: Data? = if let ps = readerAuth.coseSign1.payload.asString(), let jd = ps.data(using: .ascii) { jd } else if let bs = readerAuth.coseSign1.payload.asBytes() { Data(bs) } else { nil }
			guard let jsonData else {
				throw WalletError(description: "WRPRC cwt payload cannot be decoded", code: .invalidWrprc)
			}
			wrprcPayload = jsonData
		case .jwt(let jws):
			wrprcPayload = jws.payload
		}
		return try JSONDecoder().decode(WrpRegistrationPolicy.self, from: wrprcPayload)
	}

	/// Core WRPRC token validation shared by the presentation (OpenID4VP) and issuance (OpenID4VCI) flows.
	/// Parses the token, checks its type header, decodes the registration policy, and validates
	/// expiration, access-certificate binding, status and trust chain.
	/// - Returns: The decoded registration policy, together with typed violations for all issues found.
	static func validateWrprcCore(_ trustConfig: TrustConfiguration, wrpac: Certificate?, wrprcData: Data) async throws -> (WrpRegistrationPolicy, [RegistrationPolicyViolation]) {
		var warnings = [RegistrationPolicyViolation]()
		let wrprcToken = try x5cVerifyJwtOrCwt.parse(attestData: wrprcData, format: nil)
		let wrprcPayload: Data
		switch wrprcToken {
		case .cwt(let readerAuth):
			let type = readerAuth.coseSign1.protectedHeader.type ?? readerAuth.coseSign1.unprotectedHeader?.type
			guard let type, type == WRPRC_CWT_TYPE else {
				warnings.append(RegistrationPolicyViolation(reason: .invalidType, message: "WRPRC header type must be \(WRPRC_CWT_TYPE), got: \(type ?? "nil")"))
				let policy = try JSONDecoder().decode(WrpRegistrationPolicy.self, from: wrprcData)
				return (policy, warnings)
			}
			let jsonData: Data? = if let ps = readerAuth.coseSign1.payload.asString(), let jd = ps.data(using: .ascii) { jd } else if let bs = readerAuth.coseSign1.payload.asBytes() { Data(bs) } else { nil }
			guard let jsonData else {
				throw WalletError(description: "WRPRC cwt payload cannot be decoded", code: .invalidWrprc)
			}
			wrprcPayload = jsonData
		case .jwt(let jws):
			let type = jws.protectedHeader.type
			guard let type, type == WRPRC_JWT_TYPE else {
				warnings.append(RegistrationPolicyViolation(reason: .invalidType, message: "WRPRC header type must be \(WRPRC_JWT_TYPE), got: \(jws.protectedHeader.type ?? "nil")"))
				let policy = try JSONDecoder().decode(WrpRegistrationPolicy.self, from: jws.payload)
				return (policy, warnings)
			}
			wrprcPayload = jws.payload
		}
		let wrpIssuerPolicy = try JSONDecoder().decode(WrpRegistrationPolicy.self, from: wrprcPayload)
		if let exp = wrpIssuerPolicy.exp, Date.now > Date(timeIntervalSince1970: Double(exp)) {
			warnings.append(RegistrationPolicyViolation(reason: .expired, message: "WRPRC is expired"))
		}
		if let wrpac {
			if !wrpIssuerPolicy.isBound(to: wrpac) { warnings.append(RegistrationPolicyViolation(reason: .notBoundToAccessCertificate, message: "WRPRC not bound to requester access certificate")) }
		} else {
			warnings.append(RegistrationPolicyViolation(reason: .accessCertificateUnavailable, message: "Requester access certificate not available to check WRPRC binding"))
		}
		if let status = wrpIssuerPolicy.status {
			let statusService = DocumentStatusService(statusList: status.statusList, trustConfig: trustConfig)
			let credStatus = try? await statusService.getStatus()
			if let credStatus {
				switch credStatus {
				case .valid: break
				case .invalid:
					warnings.append(RegistrationPolicyViolation(reason: .statusRevoked, message: "WRPRC status: revoked"))
				case .suspended:
					warnings.append(RegistrationPolicyViolation(reason: .statusSuspended, message: "WRPRC status: suspended"))
				case .applicationSpecific(let code):
					warnings.append(RegistrationPolicyViolation(reason: .statusApplicationSpecific, message: "WRPRC status: application-specific (\(code))"))
				case .reserved(let code):
					warnings.append(RegistrationPolicyViolation(reason: .statusApplicationSpecific, message: "WRPRC status: reserved (\(code))"))
				}
			} else {
				Self.logger.warning("WRPRC status list could not be retrieved")
				warnings.append(RegistrationPolicyViolation(reason: .statusRetrievalFailed, message: "WRPRC status list could not be retrieved"))
			}
		} else {
			warnings.append(RegistrationPolicyViolation(reason: .statusMissing, message: "WRPRC does not have status list"))
		}
		#if canImport(EudiEtsi1196x2)
		let (isValid, reason) = try await x5cVerifyJwtOrCwt.validateTrust(wrprcToken, trustValidator: trustConfig.registrationTrustManager)
		if !isValid {
			let message = "\(wrprcToken.format.rawValue) trust error: \(reason ?? "")"
			Self.logger.warning("\(message)")
			warnings.append(RegistrationPolicyViolation(reason: .trustError, message: message))
		}
		#endif
		return (wrpIssuerPolicy, warnings)
	}
}
