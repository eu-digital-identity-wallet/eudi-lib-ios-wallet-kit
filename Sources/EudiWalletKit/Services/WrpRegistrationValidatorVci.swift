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

extension WrpRegistrationValidator {
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
				wrpWarnings.append(.init("WRPAC cannot be decoded"))
			}
			guard let wrprcData = wrprc.data(using: .ascii) else { throw WalletError(description: "WRPRC cannot be decoded", code: .invalidWrprc) }
			let wrpRegistrationPolicy = try await validateWrprcCore(wrpac: wrpacCertificate, wrprcData: wrprcData)
			var allWarnings = Self.validateOfferedConfigurations(offeredConfigurations, policy: wrpRegistrationPolicy)
			if !wrpWarnings.isEmpty { allWarnings["global", default: []].append(contentsOf: wrpWarnings.map { PolicyViolation($0.violation) }) }
			return .granted(warnings: allWarnings)
		} catch {
			wrpWarnings.append(.init("WRP policy could not be created: \(error.localizedDescription)"))
			Self.logger.error("Error in validate registration certificate: \(error)")
			return trustConfig.wrprcTrustPolicy == .enforce ?
				.notGranted(error: PolicyViolation(error.localizedDescription)) :
				.granted(warnings: ["global": [PolicyViolation(error.localizedDescription)]])
		}
	}

	/// Check each offered credential configuration against the attestations the issuer is
	/// registered to provide (`provides_attestations` claim of the WRPRC).
	/// - Returns: Warnings keyed by credential configuration identifier for uncovered configurations
	static func validateOfferedConfigurations(_ offeredConfigurations: [CredentialConfigurationIdentifier: CredentialSupported], policy: WrpRegistrationPolicy) -> [String: [PolicyViolation]] {
		guard let providedAttestations = policy.providesAttestations else { return [:] }
		var warnings = [String: [PolicyViolation]]()
		for (identifier, supported) in offeredConfigurations {
			let isCovered: Bool = switch supported {
			case .msoMdoc(let msoMdoc): providedAttestations.contains { $0.meta.doctypeValue == msoMdoc.docType }
			case .sdJwtVc(let sdJwtVc): providedAttestations.contains { attestation in
				if let vct = sdJwtVc.vct { attestation.meta.vctValues?.contains(vct) ?? false } else { false } }
			default: true
			}
			if !isCovered {
				warnings[identifier.value, default: []].append(PolicyViolation("Credential configuration \(identifier.value) is not covered by the issuer registration certificate"))
			}
		}
		return warnings
	}
}
