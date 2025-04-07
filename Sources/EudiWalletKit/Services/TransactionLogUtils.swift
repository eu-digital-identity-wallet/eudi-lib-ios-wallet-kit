import Foundation
import MdocDataTransfer18013

class TransactionLogUtils {
	@MainActor
	static let shared = TransactionLogUtils()

	private init() {}

	static func initializeTransactionLog(type: TransactionLogType, dataFormat: LogDataFormat) -> TransactionLog {
		let transactionLog = TransactionLog(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), status: .incomplete, type: type, dataFormat: dataFormat)
		return transactionLog
	}

	static func setBleTransactionLogRequestInfo(_ requestInfo: UserRequestInfo, transactionLog: inout TransactionLog) {
		transactionLog = transactionLog.copy(
			timestamp: Int64(Date.now.timeIntervalSince1970.rounded()),
			rawRequest: requestInfo.deviceRequestBytes,
			relyingParty: TransactionLogUtils.getRelyingParty(requestInfo),
			dataFormat: .cbor,
			docMetadata: Array(requestInfo.docMetadata.values),
		)
	}

	static func setBleTransactionLogResponseInfo(_ bleServerTransfer: MdocGattServer, transactionLog: inout TransactionLog) {
		let sessionTranscript: Data? = if let stb = bleServerTransfer.sessionEncryption?.sessionTranscriptBytes { Data(stb) } else { nil }
		transactionLog = transactionLog.copy(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), status: .completed, rawResponse: bleServerTransfer.deviceResponseBytes, sessionTranscript: sessionTranscript)
	}

	func getTransactionLogFilePath() -> String {
		let fileManager = FileManager.default
		let documentsDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first!
		let transactionLogFilePath = documentsDirectory.appendingPathComponent("transaction_log.json").path
		return transactionLogFilePath
	}

	func saveTransactionLog(_ log: TransactionLog) {
		let filePath = getTransactionLogFilePath()
		do {
			let data = try JSONEncoder().encode(log)
			try data.write(to: URL(fileURLWithPath: filePath))
		} catch {
			print("Error saving transaction log: \(error)")
		}
	}

	static func getRelyingParty(_ requestInfo: UserRequestInfo) -> RelyingParty? {
		guard let name = requestInfo.readerCertificateIssuer else { return nil }
		return RelyingParty(name: name, isVerified: requestInfo.readerAuthValidated ?? false, certificateChain: requestInfo.certificateChain ?? [], readerAuth: requestInfo.readerAuthBytes)
	}
}