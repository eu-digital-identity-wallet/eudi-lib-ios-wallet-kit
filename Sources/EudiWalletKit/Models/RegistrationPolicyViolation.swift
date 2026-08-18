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

/// Typed reason for a WRP registration certificate validation failure or warning.
public enum RegistrationFailureReason: Sendable, Hashable {
	/// The WRPRC `exp` claim has passed.
	case expired
	/// The WRPRC status is revoked (invalid).
	case statusRevoked
	/// The WRPRC status is suspended.
	case statusSuspended
	/// The WRPRC status is an application-specific or reserved non-valid value.
	case statusApplicationSpecific
	/// The WRPRC does not contain a status list reference.
	case statusMissing
	/// The WRPRC status list could not be retrieved.
	case statusRetrievalFailed
	/// The WRPRC trust chain could not be validated.
	case trustError
	/// The WRPRC header type is not a registration certificate type.
	case invalidType
	/// The WRPRC payload could not be decoded.
	case payloadDecodingFailed
	/// The WRPRC data could not be decoded at all.
	case invalidCertificate
	/// The WRPAC (access certificate) could not be decoded.
	case wrpacDecodingFailed
	/// The WRPRC is not bound to the requester access certificate.
	case notBoundToAccessCertificate
	/// The requester access certificate was not available to check WRPRC binding.
	case accessCertificateUnavailable
	/// A credential configuration is not covered by the issuer's `provides_attestations` claim.
	case credentialsNotCovered(credentialIds: [String])
	/// An unclassified failure.
	case other
}

/// A WRP registration certificate violation with a typed reason and human-readable message.
public struct RegistrationPolicyViolation: Sendable, Hashable {
	/// The typed failure reason.
	public let reason: RegistrationFailureReason
	/// A human-readable description of the violation.
	public let message: String

	public init(reason: RegistrationFailureReason, message: String) {
		self.reason = reason
		self.message = message
	}
}
