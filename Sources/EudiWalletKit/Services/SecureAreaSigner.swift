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
@preconcurrency import JOSESwift
import JSONWebAlgorithms
import OpenID4VCI

final class SecureAreaSigner: AsyncSignerProtocol {
	let id: String
	let secureArea: SecureArea
	let ecAlgorithm: MdocDataModel18013.SigningAlgorithm
	let algorithm: JOSESwift.SignatureAlgorithm
	let signature: Data?
	let unlockData: Data?

	init(secureArea: SecureArea, id: String, ecAlgorithm: MdocDataModel18013.SigningAlgorithm, unlockData: Data?) throws {
		self.id = id
		self.secureArea = secureArea
		self.ecAlgorithm = ecAlgorithm
		self.algorithm = try Self.getSignatureAlgorithm(ecAlgorithm)
		signature = nil
		self.unlockData = unlockData
	}

	static func getSignatureAlgorithm(_ sa: MdocDataModel18013.SigningAlgorithm) throws -> JOSESwift.SignatureAlgorithm {
		switch sa {
		case .ES256: return .ES256
		case .ES384: return .ES384
		case .ES512: return .ES512
		default: throw WalletError(description: "Invalid signing algorithm: \(sa.rawValue).")
		}
	}

	static func getSigningAlgorithm(_ sa: MdocDataModel18013.SigningAlgorithm) throws -> JSONWebAlgorithms.SigningAlgorithm {
		switch sa {
		case .ES256: return .ES256
		case .ES384: return .ES384
		case .ES512: return .ES512
		default: throw WalletError(description: "Invalid signing algorithm: \(sa.rawValue).")
		}
	}

	func sign(_ signingInput: Data) async throws -> Data {
		let ecdsaSignature = try await secureArea.signature(id: id, algorithm: ecAlgorithm, dataToSign: signingInput, unlockData: unlockData)
		return ecdsaSignature
	}

func signAsync(_ header: Data, _ payload: Data) async throws -> Data {
		let signingInput: Data? = [header as DataConvertible, payload as DataConvertible].map { $0.data().base64URLEncodedString() }
      .joined(separator: ".").data(using: .ascii)
      	guard let signingInput else {  throw ValidationError.error(reason: "Invalid signing input for signing data") }
		return try await sign(signingInput)
	}

}
