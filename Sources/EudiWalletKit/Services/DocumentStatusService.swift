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

#if canImport(EudiEtsi1196x2)
import EudiEtsi1196x2
#endif

public actor DocumentStatusService {
	let statusIdentifier: StatusIdentifier
	/// Trust configuration used to validate the reader/relying-party access certificate chain.
	public let trustConfig: TrustConfiguration
	let date: Date?
	private static let logger = Logger(label: "DocumentStatusService")

	public init(statusIdentifier: StatusIdentifier, date: Date = .now, trustConfig: TrustConfiguration) {
		self.statusIdentifier = statusIdentifier
		self.trustConfig = trustConfig
		self.date = date
	}

	public func getStatus() async throws -> CredentialStatus {
		guard let statusReference: StatusReference = .init(idx: statusIdentifier.idx, uriString: statusIdentifier.uriString) else {
			throw WalletError(description: "Invalid status identifier", code: .invalidStatusToken)
		}
		let getStatus = GetStatus()
		let tokenFetcher = StatusListTokenFetcher(
			verifier: StatusListTokenSignatureVerifier(trustConfig: trustConfig)
		)
		let result = await getStatus.getStatus(index: statusReference.idx, url: statusReference.uri, fetchClaims: tokenFetcher.getStatusClaims, clockSkew: trustConfig.clockSkew)
		switch result {
			case .success(let status): return status
			case .failure(let error): throw WalletError(description: "Status check failed", code: .statusCheckFailed, innerError: error)
		}
	}
}

struct StatusListTokenSignatureVerifier: VerifyStatusListTokenSignature {
	let trustConfig: TrustConfiguration
	private static let logger = Logger(label: "StatusListTokenSignatureVerifier")

	func verify(statusListToken: Data, format: StatusListTokenFormat, at: Date) async throws {
		let certsData: [Data]
		switch format {
		case .jwt:
			guard let jwtString = String(data: statusListToken, encoding: .utf8) else { throw JWS.JWSError.invalidString }
			try Self.verifyJwtSignature(jwt: jwtString)
			let jws = try JWS(jwsString: jwtString)
			guard let b64certs = jws.protectedHeader.x509CertificateChain else { throw JWS.JWSError.somethingWentWrong }
			certsData = b64certs.compactMap { Data(base64Encoded: $0) }
			guard certsData.count == b64certs.count else { throw JWS.JWSError.somethingWentWrong }
		case .cwt:
			let readerAuth = try ReaderAuth(data: [UInt8](statusListToken))
			certsData = readerAuth.x5chain.map { Data($0) }
		}
		guard certsData.count > 0 else { throw JWS.JWSError.somethingWentWrong }
		let (isValid, reason) = await trustConfig.accessTrustManager.validateCertTrustPath(chain: certsData)
		guard isValid else {
			let message = "\(format) status token trust error: \(reason ?? "")"
			switch trustConfig.statusTrustPolicy {
			case .warning:
				Self.logger.warning("\(message)")
				return
			case .enforce:
				throw WalletError(description: message, code: .trustError)
			}
		}
	}

	/// Verify the JWS signature against the leaf certificate carried in the `x5c` header.
	private static func verifyJwtSignature(jwt: String) throws {
		#if canImport(EudiEtsi1196x2)
		try x5cVerifyJwtSignature.verify(jwt: jwt)
		#else
		let jws = try JWS(jwsString: jwt)
		guard let leafBase64 = jws.protectedHeader.x509CertificateChain?.first, let certData = Data(base64Encoded: leafBase64) else {
			throw JWS.JWSError.missingKey
		}
		guard let certificate = SecCertificateCreateWithData(nil, certData as CFData), let publicKey = SecCertificateCopyKey(certificate) else {
			throw JWS.JWSError.missingKey
		}
		guard try jws.verify(key: publicKey) else { throw JWS.JWSError.somethingWentWrong}
		#endif
	}
}



