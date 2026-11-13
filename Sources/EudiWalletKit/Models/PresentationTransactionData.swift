/*
 * Copyright (c) 2026 European Commission
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */

import Foundation
import CryptoKit
import MdocDataModel18013
import OpenID4VP
@preconcurrency import SwiftyJSON

/// Transaction information to display before the user consents to presenting a credential.
/// Keeps the original encoded string: key-binding hashes must never hash reserialized JSON.
public struct PresentationTransactionData: Sendable {
    public enum Payload: Sendable {
        case qesRequest(QesRequest)
        case qesApprovalRequest(QesApprovalRequest)
        /// A non-QES type explicitly enabled in the wallet configuration.
        case raw(JSON)
    }

    public let encodedValue: String
    public let type: String
    public let credentialIds: [String]
    public let hashAlgorithms: [String]
    public let payload: Payload
    /// Decoded JSON for transaction logging, preserving the received bytes.
    public let jsonData: Data

    public init(encodedValue: String) throws {
        do {
            let transaction = TransactionData(value: encodedValue)
            let json = try transaction.decode()
            guard let object = json.dictionaryObject,
                  let type = object["type"] as? String, !type.isEmpty,
                  let ids = object["credential_ids"] as? [String],
                  !ids.isEmpty, ids.allSatisfy({ !$0.isEmpty }),
                  let bytes = Data(base64URLEncoded: encodedValue) else {
                throw WalletError(description: "Invalid transaction data envelope", code: .invalidTransactionData)
            }
            let algorithms: [String]
            if let value = object["transaction_data_hashes_alg"] {
                guard let names = value as? [String], !names.isEmpty, names.allSatisfy({ !$0.isEmpty }) else {
                    throw WalletError(description: "Invalid transaction_data_hashes_alg", code: .invalidTransactionData)
                }
                algorithms = names
            } else {
                algorithms = ["sha-256"]
            }
            self.encodedValue = encodedValue
            self.type = type
            self.credentialIds = ids
            self.hashAlgorithms = algorithms
            self.jsonData = bytes
            switch type {
            case QesRequest.typeIdentifier:
                payload = .qesRequest(try JSONDecoder().decode(QesRequest.self, from: bytes))
            case QesApprovalRequest.typeIdentifier:
                let approval = try JSONDecoder().decode(QesApprovalRequest.self, from: bytes)
                try requireQes(Self.approvalAlgorithms[approval.hashAlgorithmOID] != nil, "Unsupported QES hashAlgorithmOID")
                payload = .qesApprovalRequest(approval)
            default:
                payload = .raw(json)
            }
        } catch let error as WalletError {
            throw error
        } catch {
            throw WalletError(description: "Invalid transaction data: \(error.localizedDescription)", code: .invalidTransactionData, innerError: error)
        }
    }

    static let approvalAlgorithms = [
        "2.16.840.1.101.3.4.2.1": "sha-256",
        "2.16.840.1.101.3.4.2.2": "sha-384",
        "2.16.840.1.101.3.4.2.3": "sha-512"
    ]

    static func digest(_ value: String, algorithm: String) throws -> Data {
        let data = Data(value.utf8)
        switch algorithm {
        case "sha-256": return Data(SHA256.hash(data: data))
        case "sha-384": return Data(SHA384.hash(data: data))
        case "sha-512": return Data(SHA512.hash(data: data))
        default: throw WalletError(description: "Unsupported transaction hash algorithm", code: .invalidTransactionData)
        }
    }

    /// Claims for the transactions assigned to one presented credential.
    static func keyBindingClaims(_ transactions: [Self], supportedTypes: [SupportedTransactionDataType]) throws -> [String: Any] {
        guard !transactions.isEmpty else { return [:] }
        var common = Set(["sha-256", "sha-384", "sha-512"])
        for transaction in transactions {
            guard let supported = supportedTypes.first(where: { $0.type.value == transaction.type }) else {
                throw WalletError(description: "Unsupported transaction data type", code: .invalidTransactionData)
            }
            common.formIntersection(transaction.hashAlgorithms)
            common.formIntersection(supported.hashAlgorithms.map(\.name))
        }
        guard let algorithm = ["sha-256", "sha-384", "sha-512"].first(where: common.contains) else {
            throw WalletError(description: "No common transaction data hash algorithm", code: .invalidTransactionData)
        }
        var claims: [String: Any] = [
            "transaction_data_hashes_alg": algorithm,
            "transaction_data_hashes": try transactions.map { try digest($0.encodedValue, algorithm: algorithm).base64URLEncodedString() }
        ]
        let approvals = transactions.filter { if case .qesApprovalRequest = $0.payload { return true }; return false }
        try requireQes(approvals.count <= 1, "A credential cannot carry more than one QES approval")
        if let transaction = approvals.first, case .qesApprovalRequest(let approval) = transaction.payload,
           let algorithm = approvalAlgorithms[approval.hashAlgorithmOID] {
            claims["org.cloudsignatureconsortium.dm.1.qesApproval"] = try digest(transaction.encodedValue, algorithm: algorithm).base64EncodedString()
        }
        return claims
    }
}

/// Reads saved transaction data for display. Unrecognized or outdated payloads remain raw JSON.
public extension TransactionalData {
    func payloads(supportedTypes: [SupportedTransactionDataType]) -> [PresentationTransactionData.Payload] {
        content.map { object in
            guard let type = object["type"].string,
                  supportedTypes.contains(where: { $0.type.value == type }),
                  let data = try? object.rawData(),
                  let transaction = try? PresentationTransactionData(encodedValue: data.base64URLEncodedString()) else {
                return .raw(object)
            }
            return transaction.payload
        }
    }
}
