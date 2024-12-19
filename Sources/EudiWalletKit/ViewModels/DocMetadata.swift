import Foundation
import OpenID4VCI
import WalletStorage
import MdocDataModel18013

public struct DocMetadata: Sendable, Codable {
	public let docType: String?
	public func getDisplayName(_ uiCulture: String?) -> String? { display?.getName(uiCulture) }
	public let display: [Display]?
	public let namespacedClaims: [NameSpace: [String: DocClaimMetadata]]?
	public let flatClaims: [String: DocClaimMetadata]?
	
	public init(docType: String?, display: [Display]?, namespacedClaims: [NameSpace: [String: DocClaimMetadata]]? = nil, flatClaims: [String: DocClaimMetadata]? = nil) {
		self.docType = docType
		self.display = display
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
