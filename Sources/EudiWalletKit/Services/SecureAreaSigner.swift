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

class SecureAreaSigner: JOSESwift.SignerProtocol {
	let id: String
	let secureArea: SecureArea
	let ecAlgorithm: MdocDataModel18013.SigningAlgorithm
	let algorithm: JOSESwift.SignatureAlgorithm
	let unlockData: Data?
	
	init(secureArea: SecureArea, id: String, ecAlgorithm: MdocDataModel18013.SigningAlgorithm, unlockData: Data?) throws {
		self.id = id
		self.secureArea = secureArea
		self.ecAlgorithm = ecAlgorithm
		self.algorithm = try Self.getSigningAlgorithm(ecAlgorithm)
		self.unlockData = unlockData
	}
	
	static func getSigningAlgorithm(_ sa: MdocDataModel18013.SigningAlgorithm) throws -> JOSESwift.SignatureAlgorithm {
		switch sa {
		case .ES256: return .ES256
		case .ES384: return .ES384
		case .ES512: return .ES512
		default: throw WalletError(description: "Invalid signing algorithm: \(sa.rawValue).")
		}
	}

	/// Signs input data.
	///
	/// - Parameter signingInput: The input to sign.
	/// - Returns: The signature.
	/// - Throws: `JWSError` if any error occurs while signing.
	func sign(_ signingInput: Data) throws -> Data {
		let signature = try secureArea.signature(id: id, algorithm: ecAlgorithm, dataToSign: signingInput, unlockData: unlockData)
		let curveType = algorithm.curveType!
		// unpack BER encoded ASN.1 format signature to raw format as specified for JWS
		let ecSignatureTLV = [UInt8](signature.der)
		do {
				let ecSignature = try ecSignatureTLV.read(.sequence)
				let varlenR = try Data(ecSignature.read(.integer))
				let varlenS = try Data(ecSignature.skip(.integer).read(.integer))
				let fixlenR = Asn1IntegerConversion.toRaw(varlenR, of: curveType.coordinateOctetLength)
				let fixlenS = Asn1IntegerConversion.toRaw(varlenS, of: curveType.coordinateOctetLength)
				return fixlenR + fixlenS
		} catch {
				throw WalletError(description: "Could not unpack ASN.1 EC signature.")
		}

	}
	
}