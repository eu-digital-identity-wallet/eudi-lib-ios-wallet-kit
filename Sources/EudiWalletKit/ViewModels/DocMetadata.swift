import Foundation
import MdocDataModel18013

public struct DocMetadata: Sendable, Codable {
	public let docType: String?
	public let displayName: String?
	public let namespacedClaims: [NameSpace: [String: DocClaimMetadata]]?
	public let flatClaims: [String: DocClaimMetadata]?
	
	public init(docType: String?, displayName: String?, namespacedClaims: [NameSpace: [String: DocClaimMetadata]]? = nil, flatClaims: [String: DocClaimMetadata]? = nil) {
		self.docType = docType
		self.displayName = displayName
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

public struct DocClaimMetadata: Sendable, Codable {
	public let displayName: String?
	public let isMandatory: Bool?
	public let valueType: String?
}
