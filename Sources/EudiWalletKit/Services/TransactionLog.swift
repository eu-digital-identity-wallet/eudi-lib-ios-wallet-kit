import Foundation
import Logging
import XCGLogger
import MdocDataModel18013
import SiopOpenID4VP
import Copyable

/// Transaction log.
@Copyable
public struct TransactionLog: Sendable, Codable {
	public init(timestamp: Int64, status: Status, errorMessage: String? = nil, rawRequest: Data? = nil, rawResponse: Data? = nil, relyingParty: RelyingParty? = nil, type: TransactionLog.LogType, dataFormat: TransactionLog.DataFormat, sessionTranscript: Data? = nil, docMetadata: [Data?]? = nil) {
		// Initialize the properties with the provided values
		self.timestamp = timestamp
		self.status = status
		self.errorMessage = errorMessage
		self.rawRequest = rawRequest
		self.rawResponse = rawResponse
		self.relyingParty = relyingParty
		self.type = type
		self.dataFormat = dataFormat
		self.sessionTranscript = sessionTranscript
		self.docMetadata = docMetadata
	}

	public let timestamp: Int64
	public let status: Status
	public let errorMessage: String?
	public let rawRequest: Data?
	public let rawResponse: Data?
	public let relyingParty: RelyingParty?
	public let type: LogType
	public let dataFormat: DataFormat
	public let sessionTranscript: Data?
	public let docMetadata: [Data?]?

	public enum DataFormat: Int, Sendable, Codable {
		case cbor
		case json
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

	public enum LogType: Int, Sendable, Codable {
		case presentation
		case issuance
		case signing
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
	case issuance //todo
	case signing //todo
}

public struct PresentationLogData: Sendable {
	public let timestamp: Date
	public let status: TransactionLog.Status
	public let relyingParty: TransactionLog.RelyingParty
	public let documents: [DocClaimsDecodable]

	public init(_ transactionLog: TransactionLog, uiCulture: String?) {
		timestamp = Date(timeIntervalSince1970: TimeInterval(transactionLog.timestamp))
		status = transactionLog.status
		relyingParty = transactionLog.relyingParty ?? TransactionLog.RelyingParty(name: "Unidentified Relying Party", isVerified: false, certificateChain: [], readerAuth: nil)
		documents = TransactionLogUtils.parseDocClaimsDecodables(transactionLog, uiCulture: uiCulture)
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


