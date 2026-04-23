import Foundation
import Logging
import MdocDataModel18013
import OpenID4VP
import Copyable

public enum TransactionLogData: Sendable {
	case presentation(log: PresentationLogData)
	case issuance(log: IssuanceLogData)
	case deletion(log: DeletionLogData)
	case signing //todo
}

public struct PresentationLogData: Sendable {
	public let timestamp: Date
	public let status: TransactionLog.Status
	public let relyingParty: TransactionLog.RelyingParty
	public let documents: [DocClaimsModel]

	public init(_ transactionLog: TransactionLog, uiCulture: String?) {
		timestamp = Date(timeIntervalSince1970: TimeInterval(transactionLog.timestamp))
		status = transactionLog.status
		relyingParty = transactionLog.relyingParty ?? TransactionLog.RelyingParty(name: "Unidentified Relying Party", isVerified: false, certificateChain: [], readerAuth: nil)
		documents = TransactionLogUtils.parseDocClaimsDecodables(transactionLog, uiCulture: uiCulture)
	}
}

public struct IssuanceLogData: Sendable {
	public let timestamp: Date
	public let status: TransactionLog.Status
	public let issuingParty: TransactionLog.IssuingParty
	public let documentId: String?
	public let docType: String?
	public let displayName: String?
	public let dataFormat: TransactionLog.DataFormat
	public let errorMessage: String?

	public init(_ transactionLog: TransactionLog) {
		timestamp = Date(timeIntervalSince1970: TimeInterval(transactionLog.timestamp))
		status = transactionLog.status
		issuingParty = transactionLog.issuingParty ?? TransactionLog.IssuingParty(name: "Unknown Issuer", identifier: "", logoUrl: nil)
		documentId = transactionLog.documentId
		docType = transactionLog.docType
		displayName = transactionLog.displayName
		dataFormat = transactionLog.dataFormat
		errorMessage = transactionLog.errorMessage
	}
}

public struct DeletionLogData: Sendable {
	public let timestamp: Date
	public let status: TransactionLog.Status
	public let documentId: String?
	public let docType: String?
	public let displayName: String?
	public let dataFormat: TransactionLog.DataFormat
	public let errorMessage: String?

	public init(_ transactionLog: TransactionLog) {
		timestamp = Date(timeIntervalSince1970: TimeInterval(transactionLog.timestamp))
		status = transactionLog.status
		documentId = transactionLog.documentId
		docType = transactionLog.docType
		displayName = transactionLog.displayName
		dataFormat = transactionLog.dataFormat
		errorMessage = transactionLog.errorMessage
	}
}

struct VpResponsePayload: Codable {
	let verifiable_presentations: [String]
	let data_formats: [DocDataFormat]? // if dcql query
	let transaction_data: [TransactionData]?
}



