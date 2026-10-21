/*
 * Copyright (c) 2026 European Commission
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */

import CryptoKit
import MdocDataModel18013
import OpenID4VP
import SwiftCBOR

/// CSC Data Model Bindings 7.2.1.1: mdoc QES approval uses SHA-256 of the decoded
/// request bytes, unlike the SD-JWT binding, which hashes the encoded string.
enum MdocTransactionData {
    static let namespace = "org.cloudsignatureconsortium.dm.1"
    static let approvalElement = "qesApproval"

    static func deviceNameSpaces(_ transactions: [PresentationTransactionData],
                                 keyAuthorizations: KeyAuthorizations?,
                                 supportedTypes: [SupportedTransactionDataType],
                                 merging existing: DeviceNameSpaces? = nil) throws -> DeviceNameSpaces? {
        guard !transactions.isEmpty else { return existing }
        try requireQes(transactions.count == 1, "An mdoc proof cannot carry multiple QES approvals")
        let transaction = transactions[0]
        guard case .qesApprovalRequest = transaction.payload else {
            throw WalletError(description: "No mdoc binding is defined for this transaction data type", code: .invalidTransactionData)
        }
        try requireQes(supportedTypes.contains { $0.type.value == transaction.type }, "Unsupported transaction data type")
        try requireQes(keyAuthorizations?.nameSpaces?.contains(namespace) == true ||
                       keyAuthorizations?.dataElements?[namespace]?.contains(approvalElement) == true,
                       "The issuer has not authorized the mdoc key to sign qesApproval")
        let digest = CBOR.byteString(Array(SHA256.hash(data: transaction.jsonData)))
        var namespaces = existing?.deviceNameSpaces ?? [:]
        var elements = namespaces[namespace]?.deviceSignedItems ?? [:]
        if let supplied = elements[approvalElement] {
            try requireQes(supplied == digest, "Device namespaces conflict with the approved transaction data")
        }
        elements[approvalElement] = digest
        namespaces[namespace] = DeviceSignedItems(deviceSignedItems: elements)
        return DeviceNameSpaces(deviceNameSpaces: namespaces)
    }

    /// Ensure the generated response actually carries the binding. A ZK-only or incomplete
    /// response must not be dispatched as an approval without its device-signed element.
    static func validateResponse(_ response: DeviceResponse, docType: String, expected: DeviceNameSpaces) throws {
        let expectedValue = expected[namespace]?[approvalElement]
        let bound = response.documents?.contains { document in
            guard document.docType == docType,
                  case .map(let signed) = document.deviceSigned.toCBOR(options: CBOROptions()),
                  let bytes = signed[.utf8String("nameSpaces")]?.decodeTaggedBytes(),
                  let cbor = try? CBOR.decode(bytes), let namespaces = try? DeviceNameSpaces(cbor: cbor) else { return false }
            return namespaces[namespace]?[approvalElement] == expectedValue
        } == true
        try requireQes(expectedValue != nil && bound, "The mdoc response does not bind the approved transaction data")
    }
}
