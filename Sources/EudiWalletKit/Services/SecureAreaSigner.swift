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
import MdocDataModel18013
import JOSESwift

class SecureAreaSigner: SignerProtocol {
	let id: String
	let secureArea: SecureArea
	
	init(secureArea: SecureArea, id: String, algorithm: JOSESwift.SignatureAlgorithm) {
		self.id = id
		self.secureArea = secureArea
		self.algorithm = algorithm
	}
	
	var algorithm: JOSESwift.SignatureAlgorithm = .ES256
	func getSigningAlgorithm() throws ->  MdocDataModel18013.SigningAlgorithm {
		switch algorithm {
		case .ES256: return .ES256
		case .ES384: return .ES384
		case .ES512: return .ES512
		default: throw WalletError(description: "Invalid signing algorithm: \(algorithm.rawValue).")
		}
	}

	/// Signs input data.
	///
	/// - Parameter signingInput: The input to sign.
	/// - Returns: The signature.
	/// - Throws: `JWSError` if any error occurs while signing.
	func sign(_ signingInput: Data) throws -> Data {
		let signingAlgorithm = try getSigningAlgorithm()
		return try secureArea.signature(id: id, algorithm: signingAlgorithm, dataToSign: signingInput)
	}
	
}
