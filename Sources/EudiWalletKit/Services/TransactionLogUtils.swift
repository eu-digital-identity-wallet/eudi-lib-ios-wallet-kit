import Foundation
import MdocDataModel18013
import MdocDataTransfer18013
import WalletStorage
import SwiftCBOR

class TransactionLogUtils {

	static func getTimestamp() -> Int64 {
		return Int64(Date.now.timeIntervalSince1970.rounded())
	}

	static func initializeTransactionLog(type: TransactionLog.LogType, dataFormat: TransactionLog.DataFormat) -> TransactionLog {
		let transactionLog = TransactionLog(timestamp: getTimestamp(), status: .incomplete, type: type, dataFormat: dataFormat)
		return transactionLog
	}

	static func setCborTransactionLogRequestInfo(_ requestInfo: UserRequestInfo, transactionLog: inout TransactionLog) {
		transactionLog = transactionLog.copy(timestamp: getTimestamp(), rawRequest: requestInfo.deviceRequestBytes, relyingParty: TransactionLogUtils.getRelyingParty(requestInfo), dataFormat: .cbor)
	}

	static func setCborTransactionLogResponseInfo(_ bleServerTransfer: MdocGattServer, transactionLog: inout TransactionLog) {
		let sessionTranscript: Data? = if let stb = bleServerTransfer.sessionEncryption?.sessionTranscriptBytes { Data(stb) } else { nil }
		transactionLog = transactionLog.copy(timestamp: getTimestamp(), status: .completed, rawResponse: bleServerTransfer.deviceResponseBytes, dataFormat: .cbor, sessionTranscript: sessionTranscript, docMetadata: bleServerTransfer.responseMetadata)
	}

	static func setTransactionLogResponseInfo(deviceResponseBytes: Data?, dataFormat: TransactionLog.DataFormat, sessionTranscript: Data?, responseMetadata: [Data?]?, transactionLog: inout TransactionLog) {
		transactionLog = transactionLog.copy(timestamp: getTimestamp(), status: .completed, rawResponse: deviceResponseBytes, dataFormat: dataFormat, sessionTranscript: sessionTranscript, docMetadata: responseMetadata)
	}

	static func setErrorTransactionLog(type: TransactionLog.LogType, error: Error, transactionLog: inout TransactionLog) {
		transactionLog = TransactionLog(timestamp: getTimestamp(), status: .failed, errorMessage: error.localizedDescription, type: type, dataFormat: transactionLog.dataFormat)
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
				if let ps = vpResponse.presentation_submission {
					for m in ps.descriptorMap.enumerated() {
						let presentedStr = vpResponse.verifiable_presentations[m.offset]
						let dataFormat: DocDataFormat = if (m.element.toJSON()["format"] as? String) == "mso_mdoc" { .cbor } else { .sdjwt }
						let metadata = transactionLog.docMetadata?[m.offset]
						if let dcc = parseDocClaimDecodable(presentedStr, dataFormat: dataFormat, metadata: metadata, uiCulture: uiCulture) {  res.append(dcc) }

					}
				} else if let df = vpResponse.data_formats {
					for m in df.enumerated() {
						let presentedStr = vpResponse.verifiable_presentations[m.offset]
						let metadata = transactionLog.docMetadata?[m.offset]
						if let dcc = parseDocClaimDecodable(presentedStr, dataFormat: m.element, metadata: metadata, uiCulture: uiCulture) {  res.append(dcc) }
					}
				}
			} catch {
				logger.error("Error decoding transaction log JSON: \(error)")
				return []
			}
		}
		return res
	}

	static func parseDocClaimDecodable(_ presentedStr: String, dataFormat: DocDataFormat, metadata: Data?, uiCulture: String?) -> (any DocClaimsDecodable)? {
		if dataFormat == .cbor {
				if let isd = Data(base64Encoded: presentedStr), let iss = IssuerSigned(data: isd.bytes), let docDecodable = parseCBORDocClaimsDecodable(id: UUID().uuidString, docType: iss.issuerAuth.mso.docType, issuerSigned: iss, metadata: metadata, uiCulture: uiCulture) { return docDecodable }
		} else if dataFormat == .sdjwt {
				if let docDecodable = parseSdJwtDocClaimsDecodable(id: UUID().uuidString, docType: "", sdJwtSerialized: presentedStr, metadata: metadata, uiCulture: uiCulture) { return docDecodable }
		}
		return nil
	}

	static func parseCBORDocClaimsDecodable(id: String, docType: String, issuerSigned: IssuerSigned, metadata: Data?, uiCulture: String?) -> (any DocClaimsDecodable)? {
		let document = WalletStorage.Document(id: id, docType: docType, docDataFormat: .cbor, data: Data(issuerSigned.encode(options: CBOROptions())), docKeyInfo: nil, createdAt: .now, modifiedAt: .now, metadata: metadata, displayName: docType, status: .issued)
		return StorageManager.toClaimsModel(doc: document, uiCulture: uiCulture, modelFactory: nil)
	}

	static func parseSdJwtDocClaimsDecodable(id: String, docType: String, sdJwtSerialized: String, metadata: Data?, uiCulture: String?) -> (any DocClaimsDecodable)? {
		guard let sdJwtData = sdJwtSerialized.data(using: .utf8) else { return nil }
		let document = WalletStorage.Document(id: id, docType: docType, docDataFormat: .sdjwt, data: sdJwtData, docKeyInfo: nil, createdAt: .now, modifiedAt: .now, metadata: metadata, displayName: docType, status: .issued)
		return StorageManager.toClaimsModel(doc: document, uiCulture: uiCulture, modelFactory: nil)
	}

}
