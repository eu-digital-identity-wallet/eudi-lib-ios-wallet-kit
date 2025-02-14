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
@preconcurrency import OpenID4VCI
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

	public func getDisplayNames(_ uiCulture: String?) -> [String: [String: String]]? {
		let docMetadata: DocMetadata? = DocMetadata(from: metadata)
		if docDataFormat == .cbor, let ncs1 = docMetadata?.namespacedClaims?.mapValues({ nc in nc.filter({ $1.getDisplayName(uiCulture) != nil})}),
		 case let ncs = ncs1.mapValues({n1 in n1.mapValues({ $0.getDisplayName(uiCulture)! })}) { return ncs }
		if docDataFormat == .sdjwt, let ncs = docMetadata?.flatClaims?.filter({ $1.getDisplayName(uiCulture) != nil}).mapValues({ $0.getDisplayName(uiCulture)! }) { return ["": ncs] }
		return nil
	}
}

extension ClaimSet: @retroactive @unchecked Sendable {}

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
	var metadata: DocClaimMetadata { DocClaimMetadata(display: display?.map(\.displayMetadata), isMandatory: mandatory, valueType: valueType) }
}

extension CredentialConfiguration {
	func convertToDocMetadata() -> DocMetadata {
		let namespacedClaims = msoClaims?.mapValues { (claims: [String: Claim]) in
			claims.mapValues(\.metadata)
		}
		let flatClaims = flatClaims?.mapValues(\.metadata)
		return DocMetadata(credentialIssuerIdentifier: credentialIssuerIdentifier, configurationIdentifier: configurationIdentifier.value, docType: docType, display: display, issuerDisplay: issuerDisplay, namespacedClaims: namespacedClaims, flatClaims: flatClaims)
	}
}

extension DocMetadata {
	func getCborClaimMetadata(uiCulture: String?) -> (displayName: String?, display: [DisplayMetadata]?, issuerDisplay: [DisplayMetadata]?, credentialIssuerIdentifier: String?, configurationIdentifier: String?, claimDisplayNames: [NameSpace: [String: String]]?, mandatoryClaims: [NameSpace: [String: Bool]]?, claimValueTypes: [NameSpace: [String: String]]?) {
		guard let namespacedClaims = namespacedClaims else { return (nil, nil, nil, nil, nil, nil, nil, nil) }
		let claimDisplayNames = namespacedClaims.mapValues { (claims: [String: DocClaimMetadata]) in
			claims.filter { (k,v) in v.getDisplayName(uiCulture) != nil }.mapValues { $0.getDisplayName(uiCulture)!}
		}
		let mandatoryClaims = namespacedClaims.mapValues { (claims: [String: DocClaimMetadata]) in
			claims.filter { (k,v) in v.isMandatory != nil }.mapValues { $0.isMandatory!}
		}
		let claimValueTypes = namespacedClaims.mapValues { (claims: [String: DocClaimMetadata]) in
			claims.filter { (k,v) in v.valueType != nil }.mapValues { $0.valueType! }
		}
		return (getDisplayName(uiCulture), display, issuerDisplay, credentialIssuerIdentifier: credentialIssuerIdentifier, configurationIdentifier: configurationIdentifier, claimDisplayNames, mandatoryClaims, claimValueTypes)
	}

	func getFlatClaimMetadata(uiCulture: String?) -> (displayName: String?, display: [DisplayMetadata]?, issuerDisplay: [DisplayMetadata]?, credentialIssuerIdentifier: String?, configurationIdentifier: String?, claimDisplayNames: [String: String]?, mandatoryClaims: [String: Bool]?, claimValueTypes: [String: String]?) {
		guard let flatClaims = flatClaims else { return (nil, nil, nil, nil, nil, nil, nil, nil) }
		let claimDisplayNames = flatClaims.filter { (k,v) in v.getDisplayName(uiCulture) != nil }.mapValues { $0.getDisplayName(uiCulture)!}
		let mandatoryClaims = flatClaims.filter { (k,v) in v.isMandatory != nil }.mapValues { $0.isMandatory!}
		let claimValueTypes = flatClaims.filter { (k,v) in v.valueType != nil }.mapValues { $0.valueType! }
		return (getDisplayName(uiCulture), display, issuerDisplay, credentialIssuerIdentifier: credentialIssuerIdentifier, configurationIdentifier: configurationIdentifier,  claimDisplayNames, mandatoryClaims, claimValueTypes)
	}
}

extension JSON {
	func getDataValue(name: String, valueType: String?) -> (DocDataValue, String)? {
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

	func toDocClaim(_ key: String, order n: Int, _ claimDisplayNames: [String: String]?, _ mandatoryClaims: [String: Bool]?, _ claimValueTypes: [String: String]?, namespace: String? = nil) -> DocClaim? {
		let bDebug = false // UserDefaults.standard.bool(forKey: "DebugDisplay")
		if key == "cnf", type == .dictionary, !bDebug { return nil } // members used to identify the proof-of-possession key.
		if key == "status", type == .dictionary, self["status_list"].type == .dictionary, !bDebug { return nil } // status list.
		if key == "assurance_level" || key == JWTClaimNames.issuer, type == .string { if !bDebug { return nil } }
		guard let pair = getDataValue(name: key, valueType: claimValueTypes?[key]) else { return nil}
		let ch = toClaimsArray(claimDisplayNames, mandatoryClaims, claimValueTypes, namespace)
		let isMandatory = mandatoryClaims?[key] ?? true
		return DocClaim(name: key, displayName: claimDisplayNames?[key], dataValue: pair.0, stringValue: ch?.1 ?? pair.1, valueType: claimValueTypes?[key], isOptional: !isMandatory, order: n, namespace: namespace, children: ch?.0)
	}

	func toClaimsArray(_ claimDisplayNames: [String: String]?, _ mandatoryClaims: [String: Bool]?, _ claimValueTypes: [String: String]?, _ namespace: String? = nil) -> ([DocClaim], String)? {
		switch type {
		case .array, .dictionary:
			if case let claims = self["verified_claims"]["claims"], claims.type == .dictionary {
				let initialResult = self["verified_claims"]["verification"].toClaimsArray(claimDisplayNames, mandatoryClaims, claimValueTypes) ?? ([DocClaim](), "")
				return claims.reduce(into: initialResult) { (partialResult, el: (String, JSON)) in
					if let (claims1, str1) = el.1.toClaimsArray(claimDisplayNames, mandatoryClaims, claimValueTypes, el.0) {
						partialResult.0.append(contentsOf: claims1)
						partialResult.1 += (partialResult.1.count == 0 ? "" : ", ") + str1
					}
				}
			}
			var a = [DocClaim]()
			for (n,(key,subJson)) in enumerated() {
				if let di = subJson.toDocClaim(key, order: n, claimDisplayNames, mandatoryClaims, claimValueTypes) {	a.append(di) }
			}
			return (a, type == .array ? "[\(a.map(\.stringValue).joined(separator: ", "))]" : "{\(a.map { "\($0.name): \($0.stringValue)" }.joined(separator: ", "))}")
		default: return nil
		}
	}
}

extension DocClaimsDecodable {	/// Extracts display strings and images from the provided namespaces and populates the given arrays.
	///
	/// - Parameters:
	///   - nameSpaces: A dictionary where the key is a `NameSpace` and the value is an array of `IssuerSignedItem`.
	///   - docClaims: An inout parameter that will be populated with `DocClaim` items extracted from the namespaces.
	///   - labels: A dictionary where the key is the elementIdentifier and the value is a string representing the label.
	///   - nsFilter: An optional array of `NameSpace` to filter/sort the extraction. Defaults to `nil`.
	public static func extractJSONClaims(_ json: JSON, _ docClaims: inout [DocClaim], _ claimDisplayNames: [String: String]? = nil, _ mandatoryClaims: [String: Bool]? = nil, _ claimValueTypes: [String: String]? = nil) {
		let claims = json.toClaimsArray(claimDisplayNames, mandatoryClaims, claimValueTypes)?.0 ?? []
		docClaims.append(contentsOf: claims)
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




