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
import X509
import OpenID4VCI
import struct OpenID4VCI.PolicyViolation

public actor WrpVciRegistrationValidator {
	/// Trust configuration used to validate the reader/relying-party registration certificate.
	public let trustConfig: TrustConfiguration
	public let date: Date?
	public var dcqlQueryable: DefaultDcqlQueryable?
	static let logger = Logger(label: "WrpRegistrationValidator")
	static let REG_CERT_TYPE_CWT = "rc-wrp+cwt"
	/// Label of the `ItemsRequest.requestInfo` member carrying the WRPRC in ISO/IEC 18013-5 requests (ETSI TS 119 472-2)
	static let REG_CERT_REQUEST_INFO_KEY = "euWrprc"
	public var wrpRegistration: WrpRegistrationPolicy?
	public var wrpWarnings = [String:[PolicyViolation]]()
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
				wrpWarnings["", default: []].append(.init("WRPAC cannot be decoded"))
			}
			let wrprcData = wrprc.data(using: .ascii) ?? Data(base64Encoded: wrprc)
			guard let wrprcData else { throw WalletError(description: "WRPRC cannot be decoded", code: .invalidWrprc) }
			let wrpRegistrationPolicy = try await validateWrprcCore(wrpac: wrpacCertificate, wrprcData: wrprcData)
			Self.validateOfferedConfigurations(offeredConfigurations, policy: wrpRegistrationPolicy, wrpWarnings: &wrpWarnings)
			return .granted(warnings: wrpWarnings)
		} catch {
			wrpWarnings["", default: []].append(.init("WRP policy could not be created: \(error.localizedDescription)"))
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
