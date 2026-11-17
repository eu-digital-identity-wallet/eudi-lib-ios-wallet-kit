import Foundation
import OpenID4VP
import Testing
@testable import EudiWalletKit

struct CredentialQuerySelectionTests {
    private func request() throws -> DCQL {
        try JSONDecoder().decode(DCQL.self, from: Data(#"{"credentials":[{"id":"first","format":"dc+sd-jwt","multiple":true,"meta":{"vct_values":["pid"]}},{"id":"second","format":"dc+sd-jwt","meta":{"vct_values":["pid"]}}]}"#.utf8))
    }

    private func selection(_ document: String, _ query: String) throws -> CredentialSelection {
        CredentialSelection(credentialId: document, docType: "pid", queryId: try QueryId(value: query), optionId: "option", claimQueries: [])
    }

    @Test func subsetPreservesSameTypeQueryIds() throws {
        let option: CredentialSelectionSet = [try selection("a", "first"), try selection("b", "first"), try selection("c", "second")]
        let selected = try CredentialQuerySelection.select(dcql: request(), options: ["option": option], documentIds: ["b", "c"], requestName: "option")
        #expect(selected.map(\.credentialId) == ["b", "c"])
        #expect(selected.map { $0.queryIds.map(\.value) } == [["first"], ["second"]])
        let metadata = CredentialQuerySelection.metadata(try request(), option: option)
        #expect(metadata.map(\.multiple) == [true, false])
        #expect(metadata.allSatisfy { $0.required })
    }

    @Test func rejectsMissingRequiredUnknownAndEmptySelections() throws {
        let option: CredentialSelectionSet = [try selection("a", "first"), try selection("b", "first"), try selection("c", "second")]
        let dcql = try request()
        for ids: Set<String> in [[], ["a"], ["c"], ["a", "unknown"]] {
            #expect(throws: WalletError.self) {
                try CredentialQuerySelection.select(dcql: dcql, options: ["option": option], documentIds: ids, requestName: "option")
            }
        }
        #expect(throws: WalletError.self) {
            try CredentialQuerySelection.select(dcql: dcql, options: ["option": option], documentIds: ["a", "c"], requestName: "unknown")
        }
    }

    @Test func optionalSetsAndRequiredAlternatives() throws {
        let dcql = try JSONDecoder().decode(DCQL.self, from: Data(#"{"credentials":[{"id":"first","format":"dc+sd-jwt","multiple":true,"meta":{"vct_values":["pid"]}},{"id":"second","format":"dc+sd-jwt","meta":{"vct_values":["pid"]}}],"credential_sets":[{"options":[["first"]]},{"options":[["second"]],"required":false}]}"#.utf8))
        let option: CredentialSelectionSet = [try selection("a", "first"), try selection("b", "second")]
        let metadata = CredentialQuerySelection.metadata(dcql, option: option)
        #expect(metadata.map(\.required) == [true, false])
        let selected = try CredentialQuerySelection.select(dcql: dcql, options: ["option": option], documentIds: ["a"], requestName: "option")
        #expect(selected.map(\.credentialId) == ["a"])
    }

    @Test func mergedDocumentRetainsEveryQuery() throws {
        let first = try QueryId(value: "first")
        let second = try QueryId(value: "second")
        let option: CredentialSelectionSet = [CredentialSelection(credentialId: "a", docType: "pid", queryId: first, optionId: "option", claimQueries: [], queryIds: [first, second]), try selection("b", "first")]
        let selected = try CredentialQuerySelection.select(dcql: request(), options: ["option": option], documentIds: ["a"], requestName: "option")
        #expect(selected.first?.queryIds == [first, second])
    }

    @Test func unnamedSubsetRequiresOptionName() throws {
        let option: CredentialSelectionSet = [try selection("a", "first"), try selection("b", "first"), try selection("c", "second")]
        #expect(throws: WalletError.self) {
            try CredentialQuerySelection.select(dcql: request(), options: ["option": option], documentIds: ["a", "c"], requestName: nil)
        }
    }
}
