import Foundation
import Logging
import XCGLogger
import MdocDataModel18013

/**
 * A transaction log.
 * @property timestamp The timestamp of the transaction.
 * @property status The status of the transaction.
 */
public struct TransactionLog: Sendable, Codable {
    let timestamp: Int64
    let status: Status
	let errorMessage: String?
	let requestPayload: Data
	let responsePayload: Data
	let transactionType: TransactionType
	let format: LogDataFormat
}

public enum LogDataFormat: Int, Sendable, Codable {
	case cbor
	case json
	case xml
}

public enum TransactionType: Int, Sendable, Codable {
	case proximityPresentation
	case vpPresentation
}

public enum Status: Int, Sendable, Codable {
        /**
         * Indicates that the transaction is incomplete
         */
        case incomplete

        /**
         * Indicates that the transaction was completed successfully.
         */
        case completed

        /**
         * Indicates that the transaction failed.
         * @param cause the cause of the failure.
         */
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

