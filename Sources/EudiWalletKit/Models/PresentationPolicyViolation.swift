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

/// Typed reason for a WRP registration certificate validation failure or warning during presentation.
public enum PresentationFailureReason: Sendable, Hashable {
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
	/// The verifier requests claims beyond the scope allowed by the registration policy.
	case overAskedClaims(docType: String, claims: [ClaimPath]?)
	/// The WRPRC is not repeated in every ItemsRequest.requestInfo.
	case wrprcNotRepeated
	/// Different WRPRC values found across ItemsRequest.requestInfo entries.
	case wrprcMismatch
	/// The WRPRC entitlements do not include the expected operation.
	case entitlementMissing(expected: String)
	/// An unclassified failure.
	case other

	/// Maps a ``RegistrationFailureReason`` to the corresponding presentation failure reason.
	public init(registrationReason: RegistrationFailureReason) {
		switch registrationReason {
		case .expired: self = .expired
		case .statusRevoked: self = .statusRevoked
		case .statusSuspended: self = .statusSuspended
		case .statusApplicationSpecific: self = .statusApplicationSpecific
		case .statusMissing: self = .statusMissing
		case .statusRetrievalFailed: self = .statusRetrievalFailed
		case .trustError: self = .trustError
		case .invalidType: self = .invalidType
		case .payloadDecodingFailed: self = .payloadDecodingFailed
		case .invalidCertificate: self = .invalidCertificate
		case .wrpacDecodingFailed: self = .wrpacDecodingFailed
		case .notBoundToAccessCertificate: self = .notBoundToAccessCertificate
		case .accessCertificateUnavailable: self = .accessCertificateUnavailable
		default: self = .other
		}
	}
}

/// A WRP registration certificate violation with a typed reason during presentation.
public struct PresentationPolicyViolation: Sendable, Hashable {
	/// The typed failure reason.
	public let reason: PresentationFailureReason
	/// A human-readable description of the violation.
	public let message: String

	public init(reason: PresentationFailureReason, message: String) {
		self.reason = reason
		self.message = message
	}

	/// Convert from a ``RegistrationViolation`` produced by the shared core validator.
	public init(from registration: RegistrationPolicyViolation) {
		self.reason = PresentationFailureReason(registrationReason: registration.reason)
		self.message = registration.message
	}
}
