import Foundation
import Logging
import XCGLogger
import MdocDataModel18013
import SiopOpenID4VP
import Copyable

/// Transaction log.
@Copyable
public struct TransactionLog: Sendable, Codable {
	public init(timestamp: Int64, status: Status, errorMessage: String? = nil, rawRequest: Data? = nil, rawResponse: Data? = nil, relyingParty: RelyingParty? = nil, type: TransactionLogType, dataFormat: LogDataFormat) {
		self.timestamp = timestamp
		self.status = status
		self.errorMessage = errorMessage
		self.rawRequest = rawRequest
		self.rawResponse = rawResponse
		self.relyingParty = relyingParty
		self.type = type
		self.dataFormat = dataFormat
	}

    let timestamp: Int64
    let status: Status
	let errorMessage: String?
	let rawRequest: Data?
	let rawResponse: Data?
	let relyingParty: RelyingParty?
	let type: TransactionLogType
	let dataFormat: LogDataFormat
}

public enum LogDataFormat: Int, Sendable, Codable {
	case cbor
	case json
}

public struct VpRequestPayload: Codable {
	let presentationDefinition: PresentationDefinition?
	let transactionData: [TransactionData]?
}
public struct VpResponsePayload: Codable {
	let verifiablePresentations: [VerifiablePresentationPayload]
	let presentationSubmission: PresentationSubmission
	let transactionData: [TransactionData]?
}

public struct VerifiablePresentationPayload: Codable {
	let id: String
	let type: LogDataFormat
	let docData: String
	let metadata: DocMetadata?
}

public struct RelyingParty: Codable, Sendable {
	/// The name of the relying party
	let name: String
	/// Whether the relying party is verified.
	let isVerified: Bool
	/// The certificate chain of the relying party.
	let certificateChain: [Data]
	/// The reader authentication data. This is populated only when mdoc presentation is used.
	let readerAuth: Data?
}

public enum TransactionLogType: Int, Sendable, Codable {
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

/// A logger for transactions.
///
/// Implementations of this protocol should log transactions to some persistent storage.
/// The storage can be a file, a database, or any other storage medium.
public protocol TransactionLogger {
    ///  Logs a transaction.
    func log(transaction: TransactionLog)
}

/// A logger for transactions.
/// A SwiftLog implementation of the `TransactionLogger` protocol.
/// This logger logs transactions to a file using the `FileLogger` from the `swift-log-file` package.
/// The file is created in the temporary directory of the app.
/// The file is named `transaction.log`.
/// The file is rotated when it reaches a size of 1 MB.
/// The file is deleted when the app is terminated.
public struct FileTransactionLogger: TransactionLogger {
	private let logger: XCGLogger

	/// Creates a new `FileTransactionLogger` instance.
	/// - Parameter fileURL: The URL of the file to log to. If nil, a temporary file is created.
	public init(fileURL: URL? = nil) {
		let fileURL = fileURL ?? FileManager.default.temporaryDirectory.appendingPathComponent("transaction.log")
		// Create a file log destination
		let fileDestination = FileDestination(writeToFile: fileURL, identifier: "advancedLogger.fileDestination")
		// Optionally set some configuration options
		fileDestination.outputLevel = .debug
		let fileLogger = XCGLogger(identifier: "com.eudi.transaction", includeDefaultDestinations: true)
		fileLogger.add(destination: fileDestination)
		self.logger = fileLogger
	}

	/// Logs a transaction.
	/// - Parameter transaction: The transaction to log.
	public func log(transaction: TransactionLog) {
		logger.info("\(transaction.timestamp) - \(transaction.status)")
	}
}

