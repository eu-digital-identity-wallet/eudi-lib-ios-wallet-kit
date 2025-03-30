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
	public let display: [MdocDataModel18013.DisplayMetadata]?
	/// display properties of the issuer that issued the document
	public let issuerDisplay: [MdocDataModel18013.DisplayMetadata]?
	/// get display name of the issuer for the given culture
	public func getIssuerDisplayName(_ uiCulture: String?) -> String? { issuerDisplay?.getName(uiCulture) }
	/// claims metadata for the document
	public let claims: [DocClaimMetadata]?

	public init(credentialIssuerIdentifier: String, configurationIdentifier: String, docType: String?, display: [DisplayMetadata]?, issuerDisplay: [DisplayMetadata]?,  claims: [DocClaimMetadata]? = nil) {
		self.credentialIssuerIdentifier = credentialIssuerIdentifier
		self.configurationIdentifier = configurationIdentifier
		self.docType = docType
		self.display = display
		self.issuerDisplay = issuerDisplay
		self.claims = claims
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

public struct DocClaimMetadata: Sendable, Codable {
	public func getDisplayName(_ uiCulture: String?) -> String? { display?.getName(uiCulture) }
	public let display: [DisplayMetadata]?
	public let isMandatory: Bool?
	public let claimPath: [String]
}
