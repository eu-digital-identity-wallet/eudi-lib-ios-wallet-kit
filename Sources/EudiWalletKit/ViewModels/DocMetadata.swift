public struct DocMetadata: Sendable, Codable {
    public let docType: String?
    public let displayName: String?
    public let claims: [String: DocClaimMetadata]
}

public struct DocClaimMetadata: Sendable, Codable {
    public let displayName: String?
    public let isMandatory: Bool
    public let value_type: String
}
