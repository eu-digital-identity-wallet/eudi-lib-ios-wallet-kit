import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import WalletStorage
import SwiftCBOR

class TransactionLogUtils {

	static func initializeTransactionLog(type: TransactionLog.LogType, dataFormat: TransactionLog.DataFormat) -> TransactionLog {
		let transactionLog = TransactionLog(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), status: .incomplete, type: type, dataFormat: dataFormat)
		return transactionLog
	}

	static func setCborTransactionLogRequestInfo(_ requestInfo: UserRequestInfo, transactionLog: inout TransactionLog) {
		transactionLog = transactionLog.copy(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), rawRequest: requestInfo.deviceRequestBytes, relyingParty: TransactionLogUtils.getRelyingParty(requestInfo), dataFormat: .cbor)
	}

	static func setCborTransactionLogResponseInfo(_ bleServerTransfer: MdocGattServer, transactionLog: inout TransactionLog) {
		let sessionTranscript: Data? = if let stb = bleServerTransfer.sessionEncryption?.sessionTranscriptBytes { Data(stb) } else { nil }
		transactionLog = transactionLog.copy(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), status: .completed, rawResponse: bleServerTransfer.deviceResponseBytes, dataFormat: .cbor, sessionTranscript: sessionTranscript, docMetadata: bleServerTransfer.responseMetadata)
	}

	static func setTransactionLogResponseInfo(deviceResponseBytes: Data?, dataFormat: TransactionLog.DataFormat, sessionTranscript: Data?, responseMetadata: [Data?]?, transactionLog: inout TransactionLog) {
		transactionLog = transactionLog.copy(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), status: .completed, rawResponse: deviceResponseBytes, dataFormat: dataFormat, sessionTranscript: sessionTranscript, docMetadata: responseMetadata)
	}

	static func setErrorTransactionLog(type: TransactionLog.LogType, error: Error, transactionLog: inout TransactionLog) {
		transactionLog = TransactionLog(timestamp: Int64(Date.now.timeIntervalSince1970.rounded()), status: .failed, errorMessage: error.localizedDescription, type: type, dataFormat: transactionLog.dataFormat)
	}

	static func getRelyingParty(_ requestInfo: UserRequestInfo) -> TransactionLog.RelyingParty? {
		guard let name = requestInfo.readerCertificateIssuer else { return nil }
		return TransactionLog.RelyingParty(name: name, isVerified: requestInfo.readerAuthValidated ?? false, certificateChain: requestInfo.certificateChain ?? [], readerAuth: requestInfo.readerAuthBytes)
	}

	static func parseDocClaimsDecodables(_ transactionLog: TransactionLog, uiCulture: String?) -> [any DocClaimsDecodable] {
		guard let raw = transactionLog.rawResponse else { return [] }
		var res = [any DocClaimsDecodable]()
		if transactionLog.dataFormat == .cbor {
			guard let dr = DeviceResponse(data: raw.bytes) else { return [] }
			for (index, doc) in (dr.documents ?? []).enumerated() {
				let docMetadata = transactionLog.docMetadata?[index]
				if let docDecodable = parseCBORDocClaimsDecodable(id: UUID().uuidString, docType: doc.docType, issuerSigned: doc.issuerSigned, metadata: docMetadata, uiCulture: uiCulture) {
					res.append(docDecodable)
				}
			}
		} else if transactionLog.dataFormat == .json {
			let decoder = JSONDecoder()
			do {
				let vpResponse = try decoder.decode(VpResponsePayload.self, from: raw)
				for m in vpResponse.presentation_submission.descriptorMap.enumerated() {
					let presentedStr = vpResponse.verifiable_presentations[m.offset]
					if m.element.toJSON()["format"] as? String == "mso_mdoc" {
						if let isd = Data(base64Encoded: presentedStr), let iss = IssuerSigned(data: isd.bytes), let docDecodable = parseCBORDocClaimsDecodable(id: UUID().uuidString, docType: iss.issuerAuth.mso.docType, issuerSigned: iss, metadata: transactionLog.docMetadata?[m.offset], uiCulture: uiCulture) { res.append(docDecodable) }
					} else if m.element.toJSON()["format"] as? String == "vc+sd-jwt" {
						if let docDecodable = parseSdJwtDocClaimsDecodable(id: UUID().uuidString, docType: "", sdJwtSerialized: presentedStr, metadata: transactionLog.docMetadata?[m.offset], uiCulture: uiCulture) { res.append(docDecodable) }
					}
				}
			} catch {
				logger.error("Error decoding transaction log JSON: \(error)")
				return []
			}
		}
		return res
	}

	static func parseCBORDocClaimsDecodable(id: String, docType: String, issuerSigned: IssuerSigned, metadata: Data?, uiCulture: String?) -> (any DocClaimsDecodable)? {
		let document = WalletStorage.Document(id: id, docType: docType, docDataFormat: .cbor, data: Data(issuerSigned.encode(options: CBOROptions())), secureAreaName: SecureAreaRegistry.DeviceSecureArea.software.rawValue, createdAt: .now, modifiedAt: .now, metadata: metadata, displayName: docType, status: .issued)
		return StorageManager.toClaimsModel(doc: document, uiCulture: uiCulture)
	}

	static func parseSdJwtDocClaimsDecodable(id: String, docType: String, sdJwtSerialized: String, metadata: Data?, uiCulture: String?) -> (any DocClaimsDecodable)? {
		guard let sdJwtData = sdJwtSerialized.data(using: .utf8) else { return nil }
		let document = WalletStorage.Document(id: id, docType: docType, docDataFormat: .sdjwt, data: sdJwtData, secureAreaName: SecureAreaRegistry.DeviceSecureArea.software.rawValue, createdAt: .now, modifiedAt: .now, metadata: metadata, displayName: docType, status: .issued)
		return StorageManager.toClaimsModel(doc: document, uiCulture: uiCulture)
	}

}
