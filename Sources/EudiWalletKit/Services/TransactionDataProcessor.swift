/*
 * Copyright (c) 2026 European Commission
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */

import Foundation
import OpenID4VP
import MdocDataModel18013

/// Assigns each transaction exactly once, in credential_ids order, to an eligible credential.
/// The assignment is retained for both the consent UI and the resulting key-binding proof.
enum TransactionDataProcessor {
    struct Assignment {
        let documentId: String
        let queryId: String
        let transaction: PresentationTransactionData
    }

    static func canAuthorize(_ transaction: PresentationTransactionData, documentId: String,
                             mdocKeyAuthorizations: [String: KeyAuthorizations], supportedTypes: [SupportedTransactionDataType]) -> Bool {
        if let authorizations = mdocKeyAuthorizations[documentId] {
            return (try? MdocTransactionData.deviceNameSpaces([transaction], keyAuthorizations: authorizations, supportedTypes: supportedTypes)) != nil
        }
        return (try? PresentationTransactionData.keyBindingClaims([transaction], supportedTypes: supportedTypes)) != nil
    }

    static func assign(_ transactions: [PresentationTransactionData], selections: CredentialSelectionSet,
                       eligibleDocumentIds: Set<String>, mdocKeyAuthorizations: [String: KeyAuthorizations] = [:], supportedTypes: [SupportedTransactionDataType]) throws -> [Assignment] {
        var result: [Assignment] = []
        for transaction in transactions {
            var chosen: (String, String)?
            for queryId in transaction.credentialIds {
                if let selection = selections.filter({ $0.queryIds.contains { $0.value == queryId } && eligibleDocumentIds.contains($0.credentialId) &&
                    canAuthorize(transaction, documentId: $0.credentialId, mdocKeyAuthorizations: mdocKeyAuthorizations, supportedTypes: supportedTypes) })
                    .sorted(by: { $0.credentialId < $1.credentialId }).first {
                    chosen = (selection.credentialId, queryId)
                    break
                }
            }
            guard let (documentId, queryId) = chosen else {
                throw WalletError(description: "No available credential can authorize transaction data", code: .invalidTransactionData)
            }
            result.append(.init(documentId: documentId, queryId: queryId, transaction: transaction))
        }
        // A single proof has a single hash algorithm and at most one CSC approval claim.
        for document in Set(result.map(\.documentId)) {
            for query in Set(result.filter { $0.documentId == document }.map(\.queryId)) {
                let transactions = result.filter { $0.documentId == document && $0.queryId == query }.map(\.transaction)
                if let authorizations = mdocKeyAuthorizations[document] {
                    _ = try MdocTransactionData.deviceNameSpaces(transactions, keyAuthorizations: authorizations, supportedTypes: supportedTypes)
                } else {
                    _ = try PresentationTransactionData.keyBindingClaims(transactions, supportedTypes: supportedTypes)
                }
            }
        }
        return result
    }
}
