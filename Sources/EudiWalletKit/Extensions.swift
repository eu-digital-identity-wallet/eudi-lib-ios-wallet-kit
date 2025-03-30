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
import SwiftyJSON
import eudi_lib_sdjwt_swift

extension String {
	public func translated() -> String {
		NSLocalizedString(self, comment: "")
	}
}

extension Array where Element == Display {
	func getName(_ uiCulture: String?) -> String? {
		(first(where: { if #available(iOS 16, *) {
			$0.locale?.language.languageCode?.identifier == uiCulture ?? Locale.current.language.languageCode?.identifier
		} else {
				$0.locale?.languageCode == uiCulture
		} }) ?? first)?.name
	}

	func getLogo(_ uiCulture: String?) -> Display.Logo? {
		(first(where: { if #available(iOS 16, *) {
			$0.locale?.language.languageCode?.identifier == uiCulture ?? Locale.current.language.languageCode?.identifier
		} else {
				$0.locale?.languageCode == uiCulture
		} }) ?? first)?.logo
	}
}

extension Array where Element == MdocDataModel18013.DisplayMetadata {
	func getName(_ uiCulture: String?) -> String? {
		(first(where: { $0.localeIdentifier == uiCulture }) ?? first)?.name
	}
}

extension Display {
	public var displayMetadata: MdocDataModel18013.DisplayMetadata {
		let logoMetadata = LogoMetadata(urlString: logo?.uri?.absoluteString, alternativeText: logo?.alternativeText)
		return MdocDataModel18013.DisplayMetadata(name: name, localeIdentifier: locale?.identifier, logo: logoMetadata, description: description, backgroundColor: backgroundColor, textColor: textColor)
	}
}

extension Bundle {
	func getURLSchemas() -> [String]? {
		guard let urlTypes = Bundle.main.object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String:Any]], let schema = urlTypes.first, let urlSchemas = schema["CFBundleURLSchemes"] as? [String] else {return nil}
		return urlSchemas
	}
}

extension Data {
      public init?(base64urlEncoded input: String) {
          var base64 = input
          base64 = base64.replacingOccurrences(of: "-", with: "+")
          base64 = base64.replacingOccurrences(of: "_", with: "/")
          while base64.count % 4 != 0 {
              base64 = base64.appending("=")
          }
          self.init(base64Encoded: base64)
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

	public func getDisplayName(_ uiCulture: String?) -> String?  {
		let docMetadata: DocMetadata? = DocMetadata(from: metadata)
		return docMetadata?.getDisplayName(uiCulture)
	}

	public func getClaimDisplayNames(_ uiCulture: String?) -> [String: [String: String]]? {
		guard let docMetadata = DocMetadata(from: metadata) else { return nil }
		let md = docMetadata.getMetadata(uiCulture: uiCulture)
		if docDataFormat == .cbor {
			guard let cmd = md.claimMetadata?.convertToCborClaimMetadata(uiCulture) else { return nil }
			return cmd.displayNames
		} else if docDataFormat == .sdjwt {
			guard let cmd = md.claimMetadata?.convertToJsonClaimMetadata(uiCulture, key: nil) else { return nil }
			return ["": cmd.displayNames]
		}
		return nil
	}
}

extension CredentialIssuerMetadata: @retroactive @unchecked Sendable {}

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

extension AuthorizeRequestOutcome: @unchecked Sendable {
}

extension Claim {
	var metadata: DocClaimMetadata { DocClaimMetadata(display: display?.map(\.displayMetadata), isMandatory: mandatory, claimPath: path.value.map(\.description)) }
}

extension Array where Element == DocClaimMetadata {
	func convertToCborClaimMetadata(_ uiCulture: String?) -> (displayNames: [NameSpace: [String: String]], mandatory: [NameSpace: [String: Bool]]) {
		guard allSatisfy({ $0.claimPath.count > 1 }) else { return ([:], [:]) } // sanity check
		let dictNs = Dictionary(grouping: self, by: { $0.claimPath[0]})
		let dictNsAndKeys = dictNs.mapValues { Dictionary(grouping: $0, by: { $0.claimPath[1]}) } // group by namespace and key
		let displayNames = dictNsAndKeys.mapValues { nsv in nsv.compactMapValues { kv in kv.first?.display?.getName(uiCulture) } }
		let mandatory = dictNsAndKeys.mapValues { nsv in nsv.compactMapValues { kv in kv.first?.isMandatory } }
		return (displayNames, mandatory)
	}

	func convertToJsonClaimMetadata(_ uiCulture: String?, key: String?, keyIndex: Int = -1) -> (displayNames: [String: String], mandatory: [String: Bool]) {
		guard allSatisfy({ $0.claimPath.count > keyIndex + 1}) else { return ([:], [:]) } // sanity check
		let arr = if let key { filter { $0.claimPath[keyIndex] == key } } else { self }
		let dictKeys = Dictionary(grouping: arr, by: { $0.claimPath[keyIndex+1]} )
		let displayNames = dictKeys.compactMapValues { $0.first?.display?.getName(uiCulture) }
		let mandatory =  dictKeys.compactMapValues { $0.first?.isMandatory }
		return (displayNames, mandatory)
	}
}

extension CredentialConfiguration {
	func convertToDocMetadata() -> DocMetadata {
		let claimMetadata = claims.map(\.metadata)
		return DocMetadata(credentialIssuerIdentifier: credentialIssuerIdentifier, configurationIdentifier: configurationIdentifier.value, docType: docType, display: display, issuerDisplay: issuerDisplay, claims: claimMetadata)
	}
}

extension DocMetadata {
	func getMetadata(uiCulture: String?) -> (displayName: String?, display: [DisplayMetadata]?, issuerDisplay: [DisplayMetadata]?, credentialIssuerIdentifier: String?, configurationIdentifier: String?, claimMetadata: [DocClaimMetadata]?) {
		guard let claims else { return (nil, nil, nil, nil, nil, nil) }
		return (getDisplayName(uiCulture), display, issuerDisplay, credentialIssuerIdentifier: credentialIssuerIdentifier, configurationIdentifier: configurationIdentifier,  claims)
	}
}

extension JSON {
	func getDataValue(name: String) -> (DocDataValue, String)? {
		switch type {
		case .number:
			if name == "sex", let isex = Int(stringValue), isex <= 2 { return (.string(NSLocalizedString(isex == 1 ? "male" : "female", comment: "")), stringValue) }
			if name == JWTClaimNames.issuedAt || name == JWTClaimNames.expirationTime {
				let date = Date(timeIntervalSince1970: TimeInterval(intValue))
				let isoDateStr = ISO8601DateFormatter().string(from: date)
				return (.date(isoDateStr), date.formatted(date: .complete, time: .omitted))
			}
			return (.integer(UInt64(intValue)), stringValue)
		case .string:
			if name == "portrait" || name == "signature_usual_mark", let d = Data(base64urlEncoded: stringValue) { return (.bytes(d.bytes), "\(d.count) bytes") }
			return (.string(stringValue), stringValue)
		case .bool: return (.boolean(boolValue), boolValue ? "Y" : "N")
		case .array: return (.array, stringValue)
		case .dictionary:	return (.dictionary, stringValue)
		case .null:	return nil
		case .unknown: return nil
		}
	}

	func toDocClaim(_ key: String, order n: Int, pathPrefix: [String], _ claimMetadata: [DocClaimMetadata]?, _ uiCulture: String?, _ displayName: String?, _ mandatory: Bool?) -> DocClaim? {
		if key == "cnf", type == .dictionary { return nil } // members used to identify the proof-of-possession key.
		if key == "status", type == .dictionary, self["status_list"].type == .dictionary { return nil } // status list.
		if key == "assurance_level" || key == JWTClaimNames.issuer || key == JWTClaimNames.audience, type == .string {  return nil }
		if key == "vct", type == .string  { return nil }
		guard let pair = getDataValue(name: key) else { return nil}
		let ch = toClaimsArray(pathPrefix: pathPrefix + [key], claimMetadata, uiCulture)
		let isMandatory = mandatory ?? false
		return DocClaim(name: key, path: pathPrefix + [key], displayName: displayName, dataValue: pair.0, stringValue: ch?.1 ?? pair.1, isOptional: !isMandatory, order: n, namespace: nil, children: ch?.0)
	}

	func toClaimsArray(pathPrefix: [String], _ claimMetadata: [DocClaimMetadata]?, _ uiCulture: String?) -> ([DocClaim], String)? {
		switch type {
		case .array, .dictionary:
		/*
			var verified_claims = self["verified_claims"]
			if case let claims = verified_claims["claims"], claims.type == .dictionary {
				let cmd = claimMetadata?.convertToJsonClaimMetadata(uiCulture, keyPrefix: nil)
				let x = verified_claims["verification"].toClaimsArray(pathPrefix: pathPrefix, cmd?.displayNames, cmd?.mandatory)
				return claims.reduce(into: initialResult) { (partialResult, el: (String, JSON)) in
					if let (claims1, str1) = el.1.toClaimsArray(pathPrefix: pathPrefix, cmd?.displayNames, cmd?.mandatory) {
						partialResult.0.append(contentsOf: claims1)
						partialResult.1 += (partialResult.1.count == 0 ? "" : ", ") + str1
					}
				}
			}
			*/
			var a = [DocClaim]()
			for (n,(key,subJson)) in enumerated() {
				let isArray = type == .array
				let n2 = if isArray { "" } else { key }
				let cmd = claimMetadata?.convertToJsonClaimMetadata(uiCulture, key: key, keyIndex: pathPrefix.count)
				if let di = subJson.toDocClaim(n2, order: n, pathPrefix: pathPrefix, claimMetadata, uiCulture, cmd?.displayNames[key], cmd?.mandatory[key]) {
					a.append(di)
				}
			}
			return (a, type == .array ? "\(a.map(\.stringValue).joined(separator: ","))" : "{\(a.map { "\($0.name): \($0.stringValue)" }.joined(separator: ","))}")
		default: return nil
		}
	}
}


extension SecureAreaSigner: eudi_lib_sdjwt_swift.AsyncSignerProtocol {
    func signAsync(_ data: Data) async throws -> Data {
        return try await sign(data)
    }

}

extension JSON {
	func extractDigestAlgorithm() throws -> String {
		if self[Keys.sdAlg.rawValue].exists() {
			let stringValue = self[Keys.sdAlg.rawValue].stringValue
			let algorithIdentifier = HashingAlgorithmIdentifier.allCases.first(where: {$0.rawValue == stringValue})
			guard let algorithIdentifier else {
				throw SDJWTVerifierError.missingOrUnknownHashingAlgorithm
			}
			return algorithIdentifier.rawValue
		} else {
			throw SDJWTVerifierError.missingOrUnknownHashingAlgorithm
		}
	}
}




