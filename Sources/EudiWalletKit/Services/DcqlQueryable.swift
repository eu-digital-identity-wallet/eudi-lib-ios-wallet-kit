
import MdocDataModel18013
import OpenID4VP

public protocol DcqlQueryable {
	/// retrieve credential identifiers matching docType and dataFormat
	func getCredential(docOrVctType: String, docDataFormat: DocDataFormat) -> [String]
	/// retrieve all claim paths for a given credential identifier
	func getAllClaimPaths(id: String) -> [ClaimPath]
	/// check if a claim exists for a given credential identifier and claim path
	func hasClaim(id: String, claimPath: ClaimPath) -> Bool
	/// check if a claim exists for a given credential identifier and claim path and value
	func hasClaimWithValue(id: String, claimPath: ClaimPath, values: [String]) -> Bool
}

public class DefaultDcqlQueryable: DcqlQueryable {
	private let credentials: [String: (docType: String, format: DocDataFormat)]
	private let claimPaths: [String: [ClaimPath]]
	private let claimValues: [String: [ClaimPath: [String]]]

	public init(credentials: [String: (String, DocDataFormat)], claimPaths: [String: [ClaimPath]],	claimValues: [String: [ClaimPath: [String]]] = [:]) {
		self.credentials = credentials
		self.claimPaths = claimPaths
		self.claimValues = claimValues
	}

	public func getCredential(docOrVctType: String, docDataFormat: DocDataFormat) -> [String] {
		credentials.filter { _, value in
			value.docType == docOrVctType && value.format == docDataFormat
		}.map { $0.key }
	}

	public func getAllClaimPaths(id: String) -> [ClaimPath] {
		claimPaths[id] ?? []
	}

	public func hasClaim(id: String, claimPath: ClaimPath) -> Bool {
		guard let paths = claimPaths[id] else { return false }
		return paths.contains { $0.value == claimPath.value || claimPath.contains2($0) }
	}

	public func hasClaimWithValue(id: String, claimPath: ClaimPath, values: [String]) -> Bool {
		guard let claimValueMap = claimValues[id],
		      let availableValues = claimValueMap[claimPath] else {
			return false
		}
		return values.contains { availableValues.contains($0) }
	}
}
