import Foundation
import OpenID4VCI
import WalletStorage
import MdocDataModel18013

public struct DocMetadata: Sendable, Codable {
	/// the credential issuer identifier (issuer URL)
	public let credentialIssuerIdentifier: String
	/// the document configuration identifier
	public let configurationIdentifier: String
	/// the document type
	public let docType: String?
	/// get display name of the document for the given culture
	public func getDisplayName(_ uiCulture: String?) -> String? { display?.getName(uiCulture) }
	/// display properties for the document
	public let display: [Display]?
	/// display properties of the issuer that issued the document
	public let issuerDisplay: [Display]?
	/// namespaced claims (for sd-jwt documents)
	public let namespacedClaims: [NameSpace: [String: DocClaimMetadata]]?
	/// flat claims (for mso-mdoc documents)
	public let flatClaims: [String: DocClaimMetadata]?
	
	public init(credentialIssuerIdentifier: String, configurationIdentifier: String, docType: String?, display: [Display]?, issuerDisplay: [Display]?,  namespacedClaims: [NameSpace: [String: DocClaimMetadata]]? = nil, flatClaims: [String: DocClaimMetadata]? = nil) {
		self.credentialIssuerIdentifier = credentialIssuerIdentifier
		self.configurationIdentifier = configurationIdentifier
		self.docType = docType
		self.display = display
		self.issuerDisplay = issuerDisplay
		self.namespacedClaims = namespacedClaims
		self.flatClaims = flatClaims
	}
	
	public init?(from data: Data?) {
		guard let data else { return nil }
		do { self = try JSONDecoder().decode(DocMetadata.self, from: data) }
		catch { return nil }
	}
	
	public func toData() -> Data? {
		do { return try JSONEncoder().encode(self) }
		catch { return nil }
	}
}

extension Display: @retroactive @unchecked Sendable { }

public struct DocClaimMetadata: Sendable, Codable {
	public func getDisplayName(_ uiCulture: String?) -> String? { display?.getName(uiCulture) }
	public let display: [Display]?
	public let isMandatory: Bool?
	public let valueType: String?
}
