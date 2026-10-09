/*
 * Copyright (c) 2026 European Commission
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */

import Foundation
import OpenID4VP

/// The QES transaction types defined by CSC Data Model Bindings 1.0.
public extension SupportedTransactionDataType {
    static var qesRequest: Self { try! .init(type: .init(value: QesRequest.typeIdentifier)) }
    static var qesApprovalRequest: Self { try! .init(type: .init(value: QesApprovalRequest.typeIdentifier)) }
}

/// A request to authorize signatures prepared by a trust service provider.
public struct QesApprovalRequest: Codable, Sendable, Equatable {
    public static let typeIdentifier = "https://cloudsignatureconsortium.org/2025/qes-approval"
    public let type: String
    public let credentialIds: [String]
    public let hashAlgorithms: [String]?
    public let locations: [String]?
    public let credentialID: String?
    public let signatureQualifier: String?
    public let numSignatures: Int
    public let documentDigests: [QesDocumentDigest]
    public let hashAlgorithmOID: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case credentialIds = "credential_ids"
        case hashAlgorithms = "transaction_data_hashes_alg"
        case locations
        case credentialID
        case signatureQualifier
        case numSignatures
        case documentDigests
        case hashAlgorithmOID
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownQesFields(decoder, allowed: CodingKeys.allCases.map(\.rawValue))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        type = try c.decode(String.self, forKey: .type)
        credentialIds = try c.decode([String].self, forKey: .credentialIds)
        hashAlgorithms = try c.decodeIfPresent([String].self, forKey: .hashAlgorithms)
        locations = try c.decodeIfPresent([String].self, forKey: .locations)
        credentialID = try c.decodeIfPresent(String.self, forKey: .credentialID)
        signatureQualifier = try c.decodeIfPresent(String.self, forKey: .signatureQualifier)
        numSignatures = try c.decode(Int.self, forKey: .numSignatures)
        documentDigests = try c.decode([QesDocumentDigest].self, forKey: .documentDigests)
        hashAlgorithmOID = try c.decode(String.self, forKey: .hashAlgorithmOID)

        try requireQes(type == Self.typeIdentifier, "Unexpected QES approval type")
        try requireQes(!credentialIds.isEmpty && credentialIds.allSatisfy { !$0.isEmpty }, "credential_ids must not be empty")
        try requireQes(hashAlgorithms == nil || hashAlgorithms?.isEmpty == false, "transaction_data_hashes_alg must not be empty")
        try requireQes(locations == nil || locations?.isEmpty == false, "locations must not be empty")
        try requireQes(credentialID != nil || signatureQualifier != nil, "credentialID or signatureQualifier is required")
        try requireQes(numSignatures > 0, "numSignatures must be positive")
        try requireQes(!documentDigests.isEmpty, "documentDigests must not be empty")
        try requireQes(!hashAlgorithmOID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, "hashAlgorithmOID must not be blank")
    }
}

/// A request to have one or more documents signed. Signing itself belongs to the RQES application.
public struct QesRequest: Codable, Sendable, Equatable {
    public static let typeIdentifier = "https://cloudsignatureconsortium.org/2025/qes"
    public let type: String
    public let credentialIds: [String]
    public let hashAlgorithms: [String]?
    public let signatureRequests: [QesSignatureRequest]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case credentialIds = "credential_ids"
        case hashAlgorithms = "transaction_data_hashes_alg"
        case signatureRequests
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownQesFields(decoder, allowed: CodingKeys.allCases.map(\.rawValue))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        type = try c.decode(String.self, forKey: .type)
        credentialIds = try c.decode([String].self, forKey: .credentialIds)
        hashAlgorithms = try c.decodeIfPresent([String].self, forKey: .hashAlgorithms)
        signatureRequests = try c.decode([QesSignatureRequest].self, forKey: .signatureRequests)

        try requireQes(type == Self.typeIdentifier, "Unexpected QES request type")
        try requireQes(!credentialIds.isEmpty && credentialIds.allSatisfy { !$0.isEmpty }, "credential_ids must not be empty")
        try requireQes(hashAlgorithms == nil || hashAlgorithms?.isEmpty == false, "transaction_data_hashes_alg must not be empty")
        try requireQes(!signatureRequests.isEmpty, "signatureRequests must not be empty")
    }
}

/// A document fingerprint and the information needed to display or retrieve the document.
public struct QesDocumentDigest: Codable, Sendable, Equatable {
    public let label: String?
    public let hash: String
    public let hashType: String
    public let signedProperties: [QesAttribute]?
    public let circumstantialData: String?
    public let href: String?
    public let checksum: QesChecksum?
    public let access: QesAccessControlMethod?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case label
        case hash
        case hashType
        case signedProperties = "signed_props"
        case circumstantialData
        case href
        case checksum
        case access
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownQesFields(decoder, allowed: CodingKeys.allCases.map(\.rawValue))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        label = try c.decodeIfPresent(String.self, forKey: .label)
        hash = try c.decode(String.self, forKey: .hash)
        hashType = try c.decodeIfPresent(String.self, forKey: .hashType) ?? "dtbsr"
        signedProperties = try c.decodeIfPresent([QesAttribute].self, forKey: .signedProperties)
        circumstantialData = try c.decodeIfPresent(String.self, forKey: .circumstantialData)
        href = try c.decodeIfPresent(String.self, forKey: .href)
        checksum = try c.decodeIfPresent(QesChecksum.self, forKey: .checksum)
        access = try c.decodeIfPresent(QesAccessControlMethod.self, forKey: .access)

        try requireQes(["sdr", "dtbsr", "sodr"].contains(hashType), "Unsupported hashType")
        try requireQes(signedProperties == nil || signedProperties?.isEmpty == false, "signed_props must not be empty")
        try requireNonblankQes([label, hash, href])
    }
}

/// The digest used to verify a retrieved document.
public struct QesChecksum: Codable, Sendable, Equatable {
    public let value: String
    public let algorithmOID: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case value
        case algorithmOID
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownQesFields(decoder, allowed: CodingKeys.allCases.map(\.rawValue))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        value = try c.decode(String.self, forKey: .value)
        algorithmOID = try c.decode(String.self, forKey: .algorithmOID)

        try requireNonblankQes([value, algorithmOID])
    }
}

/// The access method for a referenced document. The wallet does not retrieve it automatically.
public struct QesAccessControlMethod: Codable, Sendable, Equatable {
    public let type: String
    public let oneTimePassword: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case type
        case oneTimePassword
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownQesFields(decoder, allowed: CodingKeys.allCases.map(\.rawValue))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        type = try c.decode(String.self, forKey: .type)
        oneTimePassword = try c.decodeIfPresent(String.self, forKey: .oneTimePassword)

        try requireNonblankQes([type])
        try requireQes(type != "OTP" || oneTimePassword != nil, "OTP access requires oneTimePassword")
    }
}

/// An attribute to include in a signature.
public struct QesAttribute: Codable, Sendable, Equatable {
    public let name: String
    public let value: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case name = "attribute_name"
        case value = "attribute_value"
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownQesFields(decoder, allowed: CodingKeys.allCases.map(\.rawValue))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        value = try c.decodeIfPresent(String.self, forKey: .value)

        try requireNonblankQes([name])
    }
}

/// A signature request containing exactly one inline document or document reference.
public struct QesSignatureRequest: Codable, Sendable, Equatable {
    public let signatureQualifier: String
    public let responseURI: String?
    public let signatureFormat: String?
    public let conformanceLevel: String?
    public let signedEnvelopeProperty: String?
    public let signedProperties: [QesAttribute]?
    public let referenceURI: String?
    public let label: String?
    public let document: String?
    public let documentType: String?
    public let href: String?
    public let access: QesAccessControlMethod?
    public let checksum: QesChecksum?
    public let circumstantialData: String?
    public let signAlgo: String
    public let signAlgoParams: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case signatureQualifier
        case responseURI
        case signatureFormat = "signature_format"
        case conformanceLevel = "conformance_level"
        case signedEnvelopeProperty = "signed_envelope_property"
        case signedProperties = "signed_props"
        case referenceURI = "referenceUri"
        case label
        case document
        case documentType
        case href
        case access
        case checksum
        case circumstantialData
        case signAlgo
        case signAlgoParams
    }

    public init(from decoder: Decoder) throws {
        try rejectUnknownQesFields(decoder, allowed: CodingKeys.allCases.map(\.rawValue))
        let c = try decoder.container(keyedBy: CodingKeys.self)
        signatureQualifier = try c.decode(String.self, forKey: .signatureQualifier)
        responseURI = try c.decodeIfPresent(String.self, forKey: .responseURI)
        signatureFormat = try c.decodeIfPresent(String.self, forKey: .signatureFormat)
        conformanceLevel = try c.decodeIfPresent(String.self, forKey: .conformanceLevel)
        signedEnvelopeProperty = try c.decodeIfPresent(String.self, forKey: .signedEnvelopeProperty)
        signedProperties = try c.decodeIfPresent([QesAttribute].self, forKey: .signedProperties)
        referenceURI = try c.decodeIfPresent(String.self, forKey: .referenceURI)
        label = try c.decodeIfPresent(String.self, forKey: .label)
        document = try c.decodeIfPresent(String.self, forKey: .document)
        documentType = try c.decodeIfPresent(String.self, forKey: .documentType) ?? (document != nil ? "sod" : nil)
        href = try c.decodeIfPresent(String.self, forKey: .href)
        access = try c.decodeIfPresent(QesAccessControlMethod.self, forKey: .access)
        checksum = try c.decodeIfPresent(QesChecksum.self, forKey: .checksum)
        circumstantialData = try c.decodeIfPresent(String.self, forKey: .circumstantialData)
        signAlgo = try c.decode(String.self, forKey: .signAlgo)
        signAlgoParams = try c.decodeIfPresent(String.self, forKey: .signAlgoParams)

        try requireQes((document != nil) != (href != nil), "Exactly one of document and href is required")
        if document != nil {
            try requireQes(!c.contains(.href) && !c.contains(.access) && !c.contains(.checksum), "Inline documents cannot contain reference fields")
        } else {
            try requireQes(!c.contains(.document) && !c.contains(.documentType), "Document references cannot contain inline document fields")
        }
        try requireQes(documentType == nil || ["sod", "sfd"].contains(documentType!), "Unsupported documentType")
        try requireQes(signatureFormat == nil || ["C", "X", "P", "J"].contains(signatureFormat!), "Unsupported signature_format")
        try requireQes(conformanceLevel == nil || ["AdES-B-B", "AdES-B-T", "AdES-B-LT", "AdES-B-LTA", "AdES-B", "AdES-T", "AdES-LT", "AdES-LTA"].contains(conformanceLevel!), "Unsupported conformance_level")
        try requireQes(signedEnvelopeProperty == nil || ["Detached", "Attached", "Parallel", "Certification", "Revision", "Enveloped", "Enveloping"].contains(signedEnvelopeProperty!), "Unsupported signed_envelope_property")
        try requireQes(signedProperties == nil || signedProperties?.isEmpty == false, "signed_props must not be empty")
        try requireNonblankQes([signatureQualifier, responseURI, label, document, href, signAlgo])
    }
}

private struct QesCodingKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private func rejectUnknownQesFields(_ decoder: Decoder, allowed: [String]) throws {
    let container = try decoder.container(keyedBy: QesCodingKey.self)
    let unknown = container.allKeys.map(\.stringValue).filter { !allowed.contains($0) }
    try requireQes(unknown.isEmpty, "Unknown QES fields: \(unknown.sorted().joined(separator: ", "))")
}

func requireQes(_ condition: Bool, _ message: String) throws {
    guard condition else { throw WalletError(description: message, code: .invalidTransactionData) }
}

private func requireNonblankQes(_ values: [String?]) throws {
    try requireQes(values.compactMap { $0 }.allSatisfy { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }, "QES fields must not be blank")
}
