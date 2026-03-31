import Foundation
import Logging
import MdocDataModel18013
import OpenID4VP
import Copyable

/// Transaction log.
@Copyable
public struct TransactionLog: Sendable, Codable {
	public init(timestamp: Int64, status: Status, errorMessage: String? = nil, rawRequest: Data? = nil, rawResponse: Data? = nil, relyingParty: RelyingParty? = nil, issuingParty: IssuingParty? = nil, type: TransactionLog.LogType, dataFormat: TransactionLog.DataFormat, sessionTranscript: Data? = nil, docMetadata: [Data?]? = nil, documentId: String? = nil, docType: String? = nil, displayName: String? = nil) {
		// Initialize the properties with the provided values
		self.timestamp = timestamp
		self.status = status
		self.errorMessage = errorMessage
		self.rawRequest = rawRequest
		self.rawResponse = rawResponse
		self.relyingParty = relyingParty
		self.issuingParty = issuingParty
		self.type = type
		self.dataFormat = dataFormat
		self.sessionTranscript = sessionTranscript
		self.docMetadata = docMetadata
		self.documentId = documentId
		self.docType = docType
		self.displayName = displayName
	}

	public let timestamp: Int64
	public let status: Status
	public let errorMessage: String?
	public let rawRequest: Data?
	public let rawResponse: Data?
	public let relyingParty: RelyingParty?
	public let issuingParty: IssuingParty?
	public let type: LogType
	public let dataFormat: DataFormat
	public let sessionTranscript: Data?
	public let docMetadata: [Data?]?
	public let documentId: String?
	public let docType: String?
	public let displayName: String?

	public enum DataFormat: Int, Sendable, Codable {
		case cbor
		case json

		public init(_ format: DocDataFormat) {
			switch format {
			case .cbor: self = .cbor
			case .sdjwt: self = .json
			}
		}
	}

	public struct RelyingParty: Codable, Sendable {
		/// The name of the relying party
		public let name: String
		/// Whether the relying party is verified.
		public let isVerified: Bool
		/// The certificate chain of the relying party.
		public let certificateChain: [Data]
		/// The reader authentication data. This is populated only when mdoc presentation is used.
		public let readerAuth: Data?
	}

	public struct IssuingParty: Codable, Sendable {
		public let name: String
		public let identifier: String
		public let logoUrl: String?
	}

	public enum LogType: Int, Sendable, Codable {
		case presentation
		case issuance
		case signing
		case deletion
	}

	public enum Status: Int, Sendable, Codable {
		/// Indicates that the transaction is incomplete
		case incomplete
		// Indicates that the transaction was completed successfully.
		case completed
		// Indicates that the transaction failed.
		case failed
	}
}

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

/// A logger for transactions.
///
/// Implementations of this protocol should log transactions to some persistent storage.
/// The storage can be a file, a database, or any other storage medium.
public protocol TransactionLogger: Actor {
    ///  Logs a transaction.
    func log(transaction: TransactionLog) async throws
}


