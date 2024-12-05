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

Created on 09/11/2023
*/
import Foundation
import OpenID4VCI
import MdocDataModel18013
import MdocSecurity18013
import WalletStorage
import SwiftCBOR

extension String {
	public func translated() -> String {
		NSLocalizedString(self, comment: "")
	}
}

extension Array where Element == Display {
	func getName() -> String? {
		(first(where: { $0.locale == Locale.current }) ?? first)?.name
	}
}

extension Bundle {
	func getURLSchemas() -> [String]? {
		guard let urlTypes = Bundle.main.object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String:Any]], let schema = urlTypes.first, let urlSchemas = schema["CFBundleURLSchemes"] as? [String] else {return nil}
		return urlSchemas
	}
}

extension FileManager {
	public static func getCachesDirectory() throws -> URL {
			let paths = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)
			guard paths.count > 0 else {
				throw WalletError(description: "No downloads directory found")
			}
			return paths[0]
	}
}

extension WalletStorage.Document {
	public var authorizePresentationUrl: String? {
		guard status == .pending, let model = try? JSONDecoder().decode(PendingIssuanceModel.self, from: data), case .presentation_request_url(let urlString) = model.pendingReason else { return nil	}
		return urlString
	}
}

extension ClaimSet: @retroactive @unchecked Sendable {}

extension MdocDataModel18013.CoseKeyPrivate {
  // decode private key data cbor string and save private key in key chain
	public static func from(base64: String) async -> MdocDataModel18013.CoseKeyPrivate? {
		guard let d = Data(base64Encoded: base64), let obj = try? CBOR.decode([UInt8](d)), let coseKey = CoseKey(cbor: obj), let cd = obj[-4], case let CBOR.byteString(rd) = cd else { return nil }
		let storage = await SecureAreaRegistry.shared.defaultSecurityArea!.getStorage()
		let sampleSA = SampleDataSecureArea.create(storage: storage)
		let keyData = NSMutableData(bytes: [0x04], length: [0x04].count)
		keyData.append(Data(coseKey.x)); keyData.append(Data(coseKey.y));	keyData.append(Data(rd))
		sampleSA.x963Key = keyData as Data
		let res = MdocDataModel18013.CoseKeyPrivate(secureArea: sampleSA)
		return res
	}
}

extension MdocDataModel18013.SignUpResponse {
	/// Decompose CBOR signup responses from data
	///
	/// A data file may contain signup responses with many documents (doc.types).
	/// - Parameter data: Data from file or memory
	/// - Returns:  separate json serialized signup response objects for each doc.type
	public static func decomposeCBORSignupResponse(data: Data) -> [(docType: String, jsonData: Data, drData: Data, issData: Data, pkData: Data)]? {
		guard let sr = data.decodeJSON(type: MdocDataModel18013.SignUpResponse.self), let drs = decomposeCBORDeviceResponse(data: data) else { return nil }
		return drs.compactMap { sr0 -> (docType: String, jsonData: Data, drData: Data, issData: Data, pkData: Data)? in
			let drData = Data(CBOR.encode(sr0.dr.toCBOR(options: CBOROptions())))
			let issData = Data(CBOR.encode(sr0.iss.toCBOR(options: CBOROptions())))
			var jsonObj = ["response": drData.base64EncodedString()]
			guard let jsonData = try? JSONSerialization.data(withJSONObject: jsonObj), let pk = sr.privateKey, let pkData = Data(base64Encoded: pk) else { return nil }
			jsonObj["privateKey"] = pk
			return (docType: sr0.docType, jsonData: jsonData, drData: drData, issData: issData, pkData: pkData)
		}
	}
	
	/// Device private key decoded from base64-encoded string
	public var devicePrivateKey: CoseKeyPrivate? {
		get async {
			guard let privateKey else { return nil }
			return await CoseKeyPrivate.from(base64: privateKey)
		}
	}
}

/// Extension to make BindingKey conform to Sendable
extension BindingKey: @unchecked @retroactive Sendable {
}
