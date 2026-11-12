import Foundation
import OpenID4VP

/// Constraints for a query represented in a disclosed document option.
public struct CredentialQuerySelection: Sendable {
    public let queryId: QueryId
    public let multiple: Bool
    /// Whether removing this query would leave a required credential set unsatisfied
    /// within this option. Consult `credentialSets` for grouped alternatives.
    public let required: Bool

    static func satisfiesRequiredSets(_ dcql: DCQL, queries: Set<QueryId>) -> Bool {
        guard let sets = dcql.credentialSets else {
            return Set(dcql.credentials.map(\.id)).isSubset(of: queries)
        }
        return sets.filter { $0.required ?? CredentialSetQuery.defaultRequiredValue }.allSatisfy { set in
            set.options.contains { Set($0).isSubset(of: queries) }
        }
    }

    static func metadata(_ dcql: DCQL, option: CredentialSelectionSet) -> [Self] {
        let queries = Set(option.flatMap(\.queryIds))
        return dcql.credentials.filter { queries.contains($0.id) }.map {
            Self(queryId: $0.id, multiple: $0.multiple == true,
                 required: !satisfiesRequiredSets(dcql, queries: queries.subtracting([$0.id])))
        }
    }

    /// Resolve before signing: never infer query IDs from a document's type.
    static func select(dcql: DCQL, options: CredentialSelectionSetOptions,
                       documentIds: Set<String>, requestName: String?) throws -> CredentialSelectionSet {
        guard !documentIds.isEmpty else {
            throw WalletError(description: "Select at least one credential", code: .invalidRequest)
        }
        let matches = options.filter { name, option in
            (requestName == nil || requestName == name) && documentIds.isSubset(of: Set(option.map(\.credentialId))) &&
            (requestName != nil || documentIds == Set(option.map(\.credentialId)))
        }.map { _, option in option.filter { documentIds.contains($0.credentialId) } }
        guard let selected = matches.first else {
            throw WalletError(description: "Credentials do not belong to the selected presentation option", code: .invalidRequest)
        }
        // Equality of CredentialSelection deliberately ignores query IDs, so compare mappings explicitly.
        let mapping = Dictionary(uniqueKeysWithValues: selected.map { ($0.credentialId, Set($0.queryIds)) })
        guard matches.allSatisfy({ Dictionary(uniqueKeysWithValues: $0.map { ($0.credentialId, Set($0.queryIds)) }) == mapping }) else {
            throw WalletError(description: "Ambiguous presentation option; supply requestName", code: .invalidRequest)
        }
        let queries = Set(selected.flatMap(\.queryIds))
        guard satisfiesRequiredSets(dcql, queries: queries), dcql.credentials.allSatisfy({ query in
            query.multiple == true || selected.filter { $0.queryIds.contains(query.id) }.count <= 1
        }) else {
            throw WalletError(description: "Selected credentials do not satisfy the required queries", code: .invalidRequest)
        }
        return CredentialSelectionSet(selected)
    }
}
