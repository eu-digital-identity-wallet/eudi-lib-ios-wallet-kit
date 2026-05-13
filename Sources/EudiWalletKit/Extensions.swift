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

Created on 09/11/2023
*/
import Foundation
import OpenID4VCI
import MdocDataModel18013
import MdocSecurity18013
import WalletStorage
import SwiftCBOR
import SwiftyJSON
import JOSESwift
import struct eudi_lib_sdjwt_swift.ClaimPath
import eudi_lib_sdjwt_swift

extension String {
	public func translated() -> String {
		NSLocalizedString(self, comment: "")
	}
}

func secCall<Result>(_ body: (_ resultPtr: UnsafeMutablePointer<Unmanaged<CFError>?>) -> Result?) throws -> Result {
    var errorQ: Unmanaged<CFError>? = nil
    guard let result = body(&errorQ) else {
        throw errorQ!.takeRetainedValue() as Error
    }
    return result
}

extension Display {
	public var displayMetadata: MdocDataModel18013.DisplayMetadata {
		let logoMetadata = LogoMetadata(urlString: logo?.uri?.absoluteString, alternativeText: logo?.alternativeText)
		return MdocDataModel18013.DisplayMetadata(name: name, localeIdentifier: locale?.identifier, logo: logoMetadata, description: description, backgroundColor: backgroundColor, textColor: textColor, backgroundImageURL: backgroundImage?.url.absoluteString)
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

extension Encodable {
    /// Converting object to postable JSON
    func toJSON(_ encoder: JSONEncoder = JSONEncoder()) -> [String: Any] {
        guard let data = try? encoder.encode(self),
              let object = try? JSONSerialization.jsonObject(with: data, options: .allowFragments),
              let json = object as? [String: Any] else { return [:] }
        return json
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
			guard let cmd = md.claimMetadata?.convertToJsonClaimMetadata(uiCulture, keyPrefix: nil) else { return nil }
			return ["": cmd.displayNames]
		}
		return nil
	}

	public var docTypeIdentifier: DocTypeIdentifier? {
		if docDataFormat == .cbor  { return .msoMdoc(docType: docType) }
		else if docDataFormat == .sdjwt { return .sdJwt(vct: docType) }
		else { return nil }
	}
}

/*
extension MdocDataModel18013.CoseKeyPrivate {
  // decode private key data cbor string and save private key in key chain
	public static func from(base64: String) async -> MdocDataModel18013.CoseKeyPrivate? {
		guard let d = Data(base64Encoded: base64), let obj = try? CBOR.decode([UInt8](d)), let coseKey = try? CoseKey(cbor: obj), let cd = obj[-4], case let CBOR.byteString(rd) = cd else { return nil }
		let storage = await SecureAreaRegistry.shared.defaultSecurityArea!.getStorage()
		let keyData = NSMutableData(bytes: [0x04], length: [0x04].count)
		keyData.append(Data(coseKey.x)); keyData.append(Data(coseKey.y));	keyData.append(Data(rd))
		let sampleSA = SampleDataSecureArea(storage: storage, x963Key: keyData as Data)
		let res = MdocDataModel18013.CoseKeyPrivate(secureArea: sampleSA)
		return res
	}
}
 */

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

	/*
	/// Device private key decoded from base64-encoded string
	public var devicePrivateKey: CoseKeyPrivate? {
		get async {
			guard let privateKey else { return nil }
			return await CoseKeyPrivate.from(base64: privateKey)
		}
	}
	 */
}

extension Claim {
	var metadata: DocClaimMetadata { DocClaimMetadata(display: display?.map(\.displayMetadata), isMandatory: mandatory, claimPath: path.value.map(\.description), valueType: valueType) }
}

extension Array where Element == DocClaimMetadata {
	func convertToCborClaimMetadata(_ uiCulture: String?) -> (displayNames: [NameSpace: [String: String]], mandatory: [NameSpace: [String: Bool]], valueTypes: [NameSpace: [String: String]]) {
		guard allSatisfy({ $0.claimPath.count > 1 }) else { return ([:], [:], [:]) } // sanity check
		let dictNs = Dictionary(grouping: self, by: { $0.claimPath[0]})
		let dictNsAndKeys = dictNs.mapValues { Dictionary(grouping: $0, by: { $0.claimPath[1]}) } // group by namespace and key
		let displayNames = dictNsAndKeys.mapValues { nsv in nsv.compactMapValues { kv in kv.first?.display?.getName(uiCulture) } }
		let mandatory = dictNsAndKeys.mapValues { nsv in nsv.compactMapValues { kv in kv.first?.isMandatory } }
		let valueTypes = dictNsAndKeys.mapValues { nsv in nsv.compactMapValues { kv in kv.first?.valueType } }
		return (displayNames, mandatory, valueTypes)
	}

	func convertToJsonClaimMetadata(_ uiCulture: String?, keyPrefix: [String]?) -> (displayNames: [String: String], mandatory: [String: Bool], valueTypes: [String: String], childMetadata: [DocClaimMetadata]) {
		let groupIndex = keyPrefix?.count ?? 0
		let arr = if let keyPrefix { filter { $0.claimPath.count > groupIndex && keyPrefix.elementsEqual($0.claimPath[0..<keyPrefix.count]) } } else { self }
		let dictKeys = Dictionary(grouping: arr, by: { $0.claimPath[groupIndex]} )
		let exactPathLength = groupIndex + 1
		let displayNames = dictKeys.compactMapValues { $0.first(where: { $0.claimPath.count == exactPathLength })?.display?.getName(uiCulture) }
		let mandatory =  dictKeys.compactMapValues { $0.first(where: { $0.claimPath.count == exactPathLength })?.isMandatory }
		let valueTypes = dictKeys.compactMapValues { $0.first(where: { $0.claimPath.count == exactPathLength })?.valueType }
		return (displayNames, mandatory, valueTypes, arr)
	}
}

/// Codable wrapper to persist the essential fields of AuthorizedRequest
struct AuthorizedRequestData: Codable {
	let accessToken: IssuanceAccessToken
	let refreshToken: IssuanceRefreshToken?
	let timeStamp: TimeInterval

	init(from authorized: AuthorizedRequest) {
		self.accessToken = authorized.accessToken
		self.refreshToken = authorized.refreshToken
		self.timeStamp = authorized.timeStamp
	}

	func toAuthorizedRequest() -> AuthorizedRequest {
		AuthorizedRequest(accessToken: accessToken, refreshToken: refreshToken, credentialIdentifiers: nil, timeStamp: timeStamp, dPopNonce: nil, grantType: nil)
	}
}

extension CredentialConfiguration {
	func convertToDocMetadata(authorized: AuthorizedRequest? = nil, keyOptions: KeyOptions? = nil, credentialOptions: CredentialOptions? = nil, dpopKeyId: String? = nil) -> DocMetadata {
		let claimMetadata = claims.map(\.metadata)
		let authorizedRequestData: Data? = if let authorized { try? JSONEncoder().encode(AuthorizedRequestData(from: authorized)) } else { nil }
		return DocMetadata(credentialIssuerIdentifier: credentialIssuerIdentifier, configurationIdentifier: configurationIdentifier.value, docType: docType ?? vct ?? "", display: display, issuerDisplay: issuerDisplay, claims: claimMetadata, authorizedRequestData: authorizedRequestData, keyOptions: keyOptions, credentialOptions: credentialOptions, dpopKeyId: dpopKeyId)
	}
}

extension DocMetadata {
	func getMetadata(uiCulture: String?) -> (displayName: String?, display: [DisplayMetadata]?, issuerDisplay: [DisplayMetadata]?, credentialIssuerIdentifier: String?, configurationIdentifier: String?, claimMetadata: [DocClaimMetadata]?) {
		guard let claims else { return (nil, nil, nil, nil, nil, nil) }
		return (getDisplayName(uiCulture), display, issuerDisplay, credentialIssuerIdentifier: credentialIssuerIdentifier, configurationIdentifier: configurationIdentifier,  claims)
	}

	/// Downloads all remote images referenced in the credential `display` metadata and replaces their
	/// URLs with inline `data:` URIs. This prevents issuers from learning when a user views a credential
	/// (privacy) and eliminates network latency at display time. URLs that cannot be fetched are left unchanged.
	func downloadingDisplayImages() async -> DocMetadata {
		guard let display, display.contains(where: { $0.backgroundImageURL != nil || $0.logo?.urlString != nil }) else { return self }
		let downloadedDisplay = await withTaskGroup(of: DisplayMetadata.self) { group in
			for dm in display { group.addTask { await dm.downloadingImages() } }
			var result: [DisplayMetadata] = []
			for await dm in group { result.append(dm) }
			return result
		}
		return DocMetadata(credentialIssuerIdentifier: credentialIssuerIdentifier, configurationIdentifier: configurationIdentifier, docType: docType, display: downloadedDisplay, issuerDisplay: issuerDisplay, claims: claims, authorizedRequestData: authorizedRequestData, keyOptions: keyOptions, credentialOptions: credentialOptions, dpopKeyId: dpopKeyId)
	}
}

extension DisplayMetadata {
	/// Returns a copy of this `DisplayMetadata` with any http(s) image URLs replaced by inline `data:` URIs.
	func downloadingImages() async -> DisplayMetadata {
		async let newBgURL = Self.fetchAsDataURI(urlString: backgroundImageURL)
		async let newLogoURL = Self.fetchAsDataURI(urlString: logo?.urlString)
		let (fetchedBg, fetchedLogo) = await (newBgURL, newLogoURL)
		let newLogo = logo.map { LogoMetadata(urlString: fetchedLogo ?? $0.urlString, alternativeText: $0.alternativeText) }
		return DisplayMetadata(name: name, localeIdentifier: localeIdentifier, logo: newLogo, description: description, backgroundColor: backgroundColor, textColor: textColor, backgroundImageURL: fetchedBg ?? backgroundImageURL)
	}

	/// Downloads data from `urlString` (http/https only) and encodes it as a `data:` URI.
	/// Returns `nil` if the URL is already a data URI, is `nil`, is non-http, or the download fails.
	private static func fetchAsDataURI(urlString: String?) async -> String? {
		guard let urlString else { return nil }
		// Already a data URI – nothing to do
		if urlString.lowercased().hasPrefix("data:") { return nil }
		guard let url = URL(string: urlString), url.scheme == "https" || url.scheme == "http" else { return nil }
		do {
			let (data, response) = try await URLSession.shared.data(from: url)
			let mimeType = (response as? HTTPURLResponse)?.mimeType ?? "application/octet-stream"
			return "data:\(mimeType);base64,\(data.base64EncodedString())"
		} catch {
			logger.warning("Failed to download display image from \(urlString): \(error.localizedDescription)")
			return nil
		}
	}
}

extension DocKeyInfo {
	static var `default`: Self { DocKeyInfo(secureAreaName: SoftwareSecureArea.name, batchSize: 1, credentialPolicy: .rotateUse) }
}

extension IssueRequest {
	var dpopKeyId: String { id + "_dpop" }
}

extension URL {
	func getBaseUrl() -> String {
		var urlString = scheme! + "://" + host!
		if let port = port { urlString += ":\(port)" }
		return urlString
	}
}

extension JSON {
	func getDataValue(name: String, valueType: String?) -> (DocDataValue, String)? {
		switch type {
		case .number:
			if name == "sex", let isex = Int(stringValue), isex >= 0, isex <= 2 {
				let locSexValue = NSLocalizedString(isex == 1 ? "male" : "female", comment: "")
				return (.string(locSexValue), locSexValue)
			}
			if name == JWTClaimNames.issuedAt || name == JWTClaimNames.expirationTime {
				let date = Date(timeIntervalSince1970: TimeInterval(intValue))
				let isoDateStr = ISO8601DateFormatter().string(from: date)
				return (.date(isoDateStr), date.formatted(date: .complete, time: .omitted))
			}
			return (.integer(UInt64(intValue)), stringValue)
		case .string:
			if isBase64ByteClaim(name: name, value: stringValue, valueType: valueType), let d = decodeBase64ByteClaim(stringValue) {
				return (.bytes(d.bytes), "\(d.count) bytes")
			}
			if name == "sex", let isex = Int(stringValue), isex >= 0, isex <= 2 {
				let locSexValue = NSLocalizedString(isex == 1 ? "male" : "female", comment: "")
				return (.string(locSexValue), locSexValue)
			}
			return (.string(stringValue), stringValue)
		case .bool: return (.boolean(boolValue), boolValue ? "Y" : "N")
		case .array: return (.array, stringValue)
		case .dictionary:	return (.dictionary, stringValue)
		case .null:	return nil
		case .unknown: return nil
		}
	}

	private func isBase64ByteClaim(name: String, value: String, valueType: String?) -> Bool {
		if let valueType {
			let normalized = valueType.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
			if ["jpeg", "jpg", "image/jpeg", "png", "image/png"].contains(normalized) {
				return true
			}
		}
		let (isValid, _) = isValidDataUrlAndGetCommaIndex(from: value)
		return isValid || name == "portrait" || name == "signature_usual_mark"
	}

	private func decodeBase64ByteClaim(_ value: String) -> Data? {
		if let dataUrlPayload = dataUrlBase64Payload(from: value) {
			return Data(base64Encoded: dataUrlPayload, options: .ignoreUnknownCharacters) ?? Data(base64urlEncoded: dataUrlPayload)
		}
		return Data(base64urlEncoded: value) ?? Data(base64Encoded: value)
	}

	private func isValidDataUrlAndGetCommaIndex(from value: String) -> (isValid: Bool, commaIndex: String.Index?) {
		let prefix = String(value.prefix(5))
		guard prefix.caseInsensitiveCompare("data:") == .orderedSame else { return (false, nil) }
		guard let commaIndex = value.firstIndex(of: ",") else { return (false, nil) }
		let metadataStartIndex = value.index(value.startIndex, offsetBy: 5)
		let metadata = value[metadataStartIndex..<commaIndex].lowercased()
		guard metadata.split(separator: ";").contains("base64") else { return (false, nil) }
		return (true, commaIndex)
	}

	private func dataUrlBase64Payload(from value: String) -> String? {
		let (isValid, commaIndex) = isValidDataUrlAndGetCommaIndex(from: value)
		guard isValid, let commaIndex = commaIndex else { return nil }
		return String(value[value.index(after: commaIndex)...])
	}

	func toDocClaim(key: String, order n: Int, pathPrefix: [String], claimMetadata: [DocClaimMetadata]?, uiCulture: String?, displayName: String?, mandatory: Bool?, valueType: String?) -> DocClaim? {
		if key == "_sd" || key == "_sd_alg" || key == "..." { return nil } // internal SD-JWT digest elements
		if key == "cnf", type == .dictionary { return nil } // members used to identify the proof-of-possession key.
		if key == "status", type == .dictionary, self["status_list"].type == .dictionary { return nil } // status list.
		if key == "assurance_level" || key == JWTClaimNames.issuer || key == JWTClaimNames.audience, type == .string {  return nil }
		if key == "vct", type == .string  { return nil }
		let path = pathPrefix + [key]
		guard let pair = getDataValue(name: key, valueType: valueType) else { return nil}
		let ch = toClaimsArray(pathPrefix: path, claimMetadata, uiCulture)
		let isMandatory = mandatory ?? false
		return DocClaim(name: key, path: path, displayName: displayName, dataValue: pair.0, stringValue: ch?.1 ?? pair.1, isOptional: !isMandatory, order: n, namespace: nil, children: ch?.0)
	}

	func toClaimsArray(pathPrefix: [String], _ claimMetadata: [DocClaimMetadata]?, _ uiCulture: String?) -> ([DocClaim], String)? {
		switch type {
		case .array, .dictionary:
			var a = [DocClaim]()
			for (n,(key,subJson)) in enumerated() {
				let isArray = type == .array
				let n2 = if isArray { String(n) } else { key }
				let cmd = claimMetadata?.convertToJsonClaimMetadata(uiCulture, keyPrefix: pathPrefix)
				if let di = subJson.toDocClaim(key: n2, order: n, pathPrefix: pathPrefix, claimMetadata: claimMetadata, uiCulture: uiCulture, displayName: cmd?.displayNames[key], mandatory: cmd?.mandatory[key], valueType: cmd?.valueTypes[key]) {
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
				return "sha-256"
			}
			return algorithIdentifier.rawValue
		} else {
			return "sha-256"
		}
	}
}

extension IdentityAndAccessManagementMetadata {
  public var clientAttestationPopSigningAlgValuesSupported: [JWSAlgorithm]? {
    switch self {
    case .oidc(let metaData):
      return metaData.clientAttestationPopSigningAlgValuesSupported?.map { JWSAlgorithm(name: $0) }
    case .oauth(let metaData):
      return metaData.clientAttestationPopSigningAlgValuesSupported?.map { JWSAlgorithm(name: $0) }
    }
  }
}

extension ECPublicKey: @retroactive @unchecked Sendable {}

extension CoseEcCurve {
	init?(crvName: String) {
		switch crvName {
		case "P-256": self = .P256
		case "P-384": self = .P384
		case "P-512": self = .P521
		default: return nil
		}
	}
}

extension BindingKey {

  static func createSigner(with header: JWSHeader, and payload: Payload, for privateKey: SigningKeyProxy, and signatureAlgorithm: SignatureAlgorithm) async throws -> Signer {
    if case let .secKey(secKey) = privateKey, let secKeySigner = Signer(signatureAlgorithm: signatureAlgorithm, key: secKey) {
      return secKeySigner
    } else if case let .custom(customAsyncSigner) = privateKey {
      let headerData = header as DataConvertible
      let signature = try await customAsyncSigner.signAsync(headerData.data(), payload.data())
      let customSigner = PrecomputedSigner(signature: signature, algorithm: signatureAlgorithm)
      return Signer(customSigner: customSigner)
    } else {
      throw ValidationError.error(reason: "Unable to create JWS signer")
    }
  }
}

class PrecomputedSigner: JOSESwift.SignerProtocol {
  var algorithm: JOSESwift.SignatureAlgorithm
  let signature: Data

  init(signature: Data, algorithm: JOSESwift.SignatureAlgorithm) {
    self.algorithm = algorithm
    self.signature = signature
  }

  func sign(_ signingInput: Data) throws -> Data {
    return signature
  }
}


extension DocClaim {
	var claimPath: ClaimPath {
		ClaimPath(path.map { if let index = Int($0) { ClaimPathElement.arrayElement(index: index) } else if $0.isEmpty { ClaimPathElement.allArrayElements } else { ClaimPathElement.claim(name: $0) } })
	}
	var claimPaths: [ClaimPath] {
		if let children { children.map(\.claimPath) } else { [claimPath] }
	}
}

extension DocClaimsModelConfiguration {
	init(from model: DocClaimsModel) {
		self.init(
			id: model.id, createdAt: model.createdAt, docType: model.docType,
			displayName: model.displayName, display: model.display, issuerDisplay: model.issuerDisplay,
			credentialIssuerIdentifier: model.credentialIssuerIdentifier,
			configurationIdentifier: model.configurationIdentifier,
			validFrom: model.validFrom, validUntil: model.validUntil,
			statusIdentifier: model.statusIdentifier,
			credentialsUsageCounts: model.credentialsUsageCounts,
			credentialPolicy: model.credentialPolicy, secureAreaName: model.secureAreaName,
			modifiedAt: model.modifiedAt, ageOverXX: model.ageOverXX,
			docClaims: model.docClaims, docDataFormat: model.docDataFormat,
			hashingAlg: model.hashingAlg, nameSpaces: model.nameSpaces
		)
	}

	func withDocClaims(_ docClaims: [DocClaim]) -> DocClaimsModelConfiguration {
		DocClaimsModelConfiguration(
			id: id, createdAt: createdAt, docType: docType,
			displayName: displayName, display: display, issuerDisplay: issuerDisplay,
			credentialIssuerIdentifier: credentialIssuerIdentifier,
			configurationIdentifier: configurationIdentifier,
			validFrom: validFrom, validUntil: validUntil,
			statusIdentifier: statusIdentifier,
			credentialsUsageCounts: credentialsUsageCounts,
			credentialPolicy: credentialPolicy, secureAreaName: secureAreaName,
			modifiedAt: modifiedAt, ageOverXX: ageOverXX,
			docClaims: docClaims, docDataFormat: docDataFormat,
			hashingAlg: hashingAlg, nameSpaces: nameSpaces
		)
	}
}

extension EudiWallet {
	/// Try to resolve a pre-registered VCI service directly from credential offer URL parameters.
	func resolveVCIServiceFromOfferUri(_ offerUri: String) async -> OpenId4VciService? {
		guard let issuerURL = Self.extractCredentialIssuerURL(from: offerUri) else { return nil }
		return await OpenId4VCIServiceRegistry.shared.getByIssuerURL(issuerURL: issuerURL)
	}

	/// Extract credential issuer URL from an OpenID4VCI offer URL.
	static func extractCredentialIssuerURL(from offerUri: String) -> String? {
		guard let components = URLComponents(string: offerUri) else { return nil }
		guard let encodedOffer = components.queryItems?.first(where: { $0.name == "credential_offer" })?.value else {
			return nil
		}
		let decodedOffer = encodedOffer.removingPercentEncoding ?? encodedOffer
		guard let offerData = decodedOffer.data(using: .utf8),
			  let payload = try? JSONSerialization.jsonObject(with: offerData) as? [String: Any],
			  let credentialIssuer = payload["credential_issuer"] as? String,
			  !credentialIssuer.isEmpty else {
			return nil
		}
		return credentialIssuer
	}
}
