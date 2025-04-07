import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import WalletStorage
import SwiftCBOR

class TransactionLogUtils {
	@MainActor
	static let shared = TransactionLogUtils()

	private init() {}

	static func initializeTransactionLog(type: TransactionLog.LogType, dataFormat: TransactionLog.DataFormat) -> TransactionLog {
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

/*
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
	*/

	static func getRelyingParty(_ requestInfo: UserRequestInfo) -> TransactionLog.RelyingParty? {
		guard let name = requestInfo.readerCertificateIssuer else { return nil }
		return TransactionLog.RelyingParty(name: name, isVerified: requestInfo.readerAuthValidated ?? false, certificateChain: requestInfo.certificateChain ?? [], readerAuth: requestInfo.readerAuthBytes)
	}

	static func parseDocClaimsDecodables(_ transactionLog: TransactionLog, uiCulture: String?) -> [any DocClaimsDecodable] {
		guard let raw = transactionLog.rawResponse else { return [] }
		var res = [any DocClaimsDecodable]()
		let docMetadatas = transactionLog.docMetadata?.compactMap { DocMetadata(from: Data?($0)) } ?? []
		if transactionLog.dataFormat == .cbor {
			guard let dr = DeviceResponse(data: raw.bytes) else { return [] }
			for doc in dr.documents ?? [] {
				let docMetadata = docMetadatas.first(where: { $0.docType == doc.docType })
				if let docDecodable = parseCBORDocClaimsDecodable(id: docMetadata?.docId ?? UUID().uuidString, docType: doc.docType, issuerSigned: doc.issuerSigned, metadata: docMetadata?.toData(), uiCulture: uiCulture) {
					res.append(docDecodable)
				}
			}
		}
		return res
	}

	static func parseCBORDocClaimsDecodable(id: String, docType: String, issuerSigned: IssuerSigned, metadata: Data?, uiCulture: String?) -> (any DocClaimsDecodable)? {
		let document = WalletStorage.Document(id: id, docType: docType, docDataFormat: .cbor, data: Data(issuerSigned.encode(options: CBOROptions())), secureAreaName: SecureAreaRegistry.DeviceSecureArea.software.rawValue, createdAt: .now, modifiedAt: .now, metadata: metadata, displayName: docType, status: .issued)
		return StorageManager.toClaimsModel(doc: document, uiCulture: uiCulture)
	}
}