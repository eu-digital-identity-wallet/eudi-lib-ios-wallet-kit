/*
Copyright (c) 2023 European Commission

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
import CryptoKit
import X509

/// Issue request structure
public struct IssueRequest {
	let secureKey: SecureEnclave.P256.Signing.PrivateKey
	let certificate: SecCertificate?
	var publicKey: Data { secureKey.publicKey.derRepresentation }
	
	
	/// Initialize issue request
	/// - Parameters:
	///   - certificate: Root certificate (optional)
	///   - savedKey: saved key representation (optional)
	public init(certificate: SecCertificate? = nil, savedKey: Data? = nil) throws {
		self.certificate = certificate
		secureKey = if let savedKey { try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: savedKey) } else { try SecureEnclave.P256.Signing.PrivateKey() }
	}
	
	
	/// Sign data with ``secureKey``
	/// - Parameter data: Data to be signed
	/// - Returns: DER representation of signture for SHA256  hash
	func signData(_ data: Data) throws -> Data {
		let signature: P256.Signing.ECDSASignature = try secureKey.signature(for: SHA256.hash(data: data))
		return signature.derRepresentation
	}
	
	//func certificateTrust(certificate: SecCertificate) -> ver
}


