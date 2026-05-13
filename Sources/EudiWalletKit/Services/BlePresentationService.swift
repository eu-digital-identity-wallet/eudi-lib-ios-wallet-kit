/*
Copyright (c) 2026 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import Foundation
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import struct WalletStorage.Document

/// Implements proximity attestation presentation with QR to BLE data transfer

/// Implementation is based on the ISO/IEC 18013-5 specification

public final class BlePresentationService: @unchecked Sendable, PresentationService {
	var bleTranport: any MdocBleTransport
	var bleServer: MdocGattServer?
	let bleTransferMode: BleTransferMode
	public var status: TransferStatus = .initialized
	var isPeripheralManagerPoweredOn = false
	var isCentralManagerPoweredOn = false
	var continuationPowerOn: CheckedContinuation<Void, Error>?
	var continuationRequest: CheckedContinuation<UserRequestInfo, Error>?
	var continuationDisconnect: CheckedContinuation<Void, Error>?
	var handleSelected: ((Bool, RequestItems?) async -> Void)?
	var request: UserRequestInfo?
	var readBuffer = Data()
	public var transactionLog: TransactionLog
	public var documentIds: [Document.ID] = []
	public var zkpDocumentIds: [Document.ID]?
	public var flow: FlowType { .ble }
	public var deviceEngagement: DeviceEngagement?
	public var deviceRequest: DeviceRequest?
	public var sessionEncryption: SessionEncryption?
	public var docs: [String: IssuerSigned]!
	public var docMetadata: [String: Data?]!
	public var iaca: [x5chain]!
	public var privateKeyObjects: [String: CoseKeyPrivate]!
	public var dauthMethod: DeviceAuthMethod
	public var zkSystemRepository: ZkSystemRepository?
	public var readerName: String?
	public var qrCodePayload: String?
	public var unlockData: [String: Data]!
	public var deviceResponseBytes: Data?
	public var responseMetadata: [Data?]!

	public init(parameters: InitializeTransferData, bleTransferMode: BleTransferMode) async throws {
		let objs = try await parameters.toInitializeTransferInfo()
		self.docs = try objs.documentObjects.mapValues { try IssuerSigned(data: $0.bytes) }
		docMetadata = parameters.docMetadata
		self.privateKeyObjects = objs.privateKeyObjects
		self.iaca = objs.iaca
		self.dauthMethod = objs.deviceAuthMethod
		self.zkSystemRepository = objs.zkSystemRepository
		self.bleTransferMode = bleTransferMode
		bleTranport = bleTransferMode == .server ? MdocGattServer() : MdocGattCentral()
		if bleTransferMode == .both { bleServer = MdocGattServer() }
		transactionLog = TransactionLogUtils.initializeTransactionLog(type: .presentation, dataFormat: .cbor)
		bleTranport.delegate = self
		bleServer?.delegate = self
	}
	
	var isInErrorState: Bool { status == .error }
	// Create a new device engagement object and start the device engagement process.
	///
	/// ``qrCodePayload`` is set to QR code data corresponding to the device engagement.
	public func performDeviceEngagement(secureArea: any SecureArea, crv: CoseEcCurve, rfus: [String]? = nil) async throws {
		if unlockData == nil {
			unlockData = [String: Data]()
			for (id, key) in privateKeyObjects {
				let ud = try await key.secureArea.unlockKey(id: id)
				if let ud { unlockData[id] = ud }
			}
		}

		guard !isInErrorState else {
			logger.info("Current status is \(status)")
			return
		}
		// Check that the class is in the right state to start the device engagement process. It will fail if the class is in any other state.
		guard status == .initialized || status == .disconnected || status == .responseSent else {
			throw MdocHelpers.makeError(code: .unexpected_error, str: "Not initialized!")
		}
		// todo: issuerNameSpaces is not mandatory according to specs, need to change
		guard docs.values.allSatisfy({ $0.issuerNameSpaces != nil }) else {
			throw MdocHelpers.makeError(code: .invalidInputDocument)
		}
		deviceEngagement = DeviceEngagement(supportsCentralClientMode: bleTransferMode == .client || bleTransferMode == .both, supportsPeripheralServerMode: bleTransferMode == .server || bleTransferMode == .both, rfus: rfus)
		try await deviceEngagement!.makePrivateKey(crv: crv, secureArea: secureArea)
		sessionEncryption = nil
#if os(iOS)
		qrCodePayload = deviceEngagement!.getQrCodePayload()
		guard bleTranport.isAuthorized else {
			throw MdocHelpers.makeError(code: .bleNotAuthorized)
		}
		//if !bleTranport.isBlePoweredOn {
			try await withCheckedThrowingContinuation { c in
				continuationPowerOn = c
				evaluatePowerOnStatus()
			}
		//} // ensure that BLE is powered on before proceeding
		continuationPowerOn = nil
		status = .qrEngagementReady
		logger.info("Created qrCode payload: \(qrCodePayload!)")
#endif
		bleTranport.startBleAdvertising()
		bleServer?.startBleAdvertising()
	}

	/// Generate device engagement QR code

	/// The holder app should present the returned code to the verifier
	/// - Returns: The image data for the QR code
	public func startQrEngagement(secureAreaName: String?, crv: CoseEcCurve) async throws -> String {
		try await performDeviceEngagement(secureArea: SecureAreaRegistry.shared.get(name: secureAreaName), crv: crv)
		return status == .qrEngagementReady ? (qrCodePayload ?? "") : ""
	}

	
	func handleStatusChange(_ newValue: TransferStatus) async {
		guard !isInErrorState else {
			return
		}
		logger.log(level: .info, "Transfer status will change to \(newValue)")
		switch newValue {
		case .requestReceived:
			bleTranport.stopBleAdvertising()
			bleServer?.stopBleAdvertising()
			let decodedRes = await MdocHelpers.decodeRequestAndInformUser(deviceEngagement: deviceEngagement, docs: docs, docMetadata: docMetadata.compactMapValues { $0 }, iaca: iaca, requestData: readBuffer, privateKeyObjects: privateKeyObjects, dauthMethod: dauthMethod, unlockData: unlockData, readerKeyRawData: nil, handOver: BleTransferMode.QRHandover)
			switch decodedRes {
			case .success(let decoded):
				deviceRequest = decoded.deviceRequest
				sessionEncryption = decoded.sessionEncryption
				if decoded.isValidRequest {
					self.handleSelected = userSelected
					continuationRequest?.resume(returning: decoded.userRequestInfo)
					continuationRequest = nil
				} else {
					await userSelected(false, nil)
					didFinishedWithError(NSError(domain: "\(MdocGattServer.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: "The requested document is not available in your EUDI Wallet. Please contact the authorised issuer for further information."]))
				}
			case .failure(let err):
				didFinishedWithError(err)
				return
			}
		case .connected: break
		case .disconnected where status != .disconnected:
			stop()
		case .poweredOn: break
		case .qrEngagementReady:
			break
		case .disconnected:
			continuationDisconnect?.resume(returning: ())
			continuationDisconnect = nil
		default: break
		}
	}
	
	public func stop() {
		bleTranport.stop()
		bleServer?.stop()
		sessionEncryption = nil
		qrCodePayload = nil
		if let pk = deviceEngagement?.privateKey {
			Task { @MainActor in
				try? await pk.secureArea.deleteKeyBatch(id: pk.privateKeyId, startIndex: 0, batchSize: 1)
				deviceEngagement?.privateKey = nil
			}
		}
		if status == .error {
			status = .initializing
		}
	}

	public func userSelected(_ b: Bool, _ items: RequestItems?) async {
		status = .userSelected
		let resError = await MdocHelpers.getSessionDataToSend(sessionEncryption: sessionEncryption, status: .error, docToSend: DeviceResponse(status: 0))
		var bytesToSend = try! resError.get()
		deviceResponseBytes = bytesToSend.1
		var errorToSend: Error?
		defer {
			logger.info("Prepare \(bytesToSend.0.count) bytes to send")
			bleTranport.sendData(bytesToSend.0)
		}
		if !b {
			errorToSend = MdocHelpers.makeError(code: .userRejected)
		}
		if let items {
			do {
				let docTypeReq = deviceRequest?.docRequests.first?.itemsRequest.docType ?? ""
				guard let (drToSend, _, _, resMetadata, resDocIds, resZkpDocIds) = try await MdocHelpers.getDeviceResponseToSend(deviceRequest: deviceRequest!, issuerSigned: docs, docMetadata: docMetadata.compactMapValues { $0 }, selectedItems: items, sessionEncryption: sessionEncryption, eReaderKey: sessionEncryption!.sessionKeys.publicKey, privateKeyObjects: privateKeyObjects, dauthMethod: dauthMethod, unlockData: unlockData, zkSystemRepository: zkSystemRepository) else {
					errorToSend = MdocHelpers.getErrorNoDocuments(docTypeReq)
					return
				}
				guard !drToSend.documents.isNilOrEmpty || !drToSend.zkDocuments.isNilOrEmpty else {
					errorToSend = MdocHelpers.getErrorNoDocuments(docTypeReq)
					return
				}
				let dataRes = await MdocHelpers.getSessionDataToSend(sessionEncryption: sessionEncryption, status: .requestReceived, docToSend: drToSend)
				switch dataRes {
				case .success(let bytes):
					bytesToSend = bytes
					deviceResponseBytes = bytes.1
					responseMetadata = resMetadata
					documentIds = resDocIds
					zkpDocumentIds = resZkpDocIds
				case .failure(let err):
					errorToSend = err
					return
				}
			} catch {
				errorToSend = error
			}
			if let errorToSend {
				logger.error("Error sending data: \(errorToSend)")
			}
		}
	}

	///  Receive request via BLE
	///
	/// - Returns: The requested items.
	public func receiveRequest() async throws -> UserRequestInfo {
		let userRequestInfo = try await withCheckedThrowingContinuation { c in
			continuationRequest = c
		}
		TransactionLogUtils.setCborTransactionLogRequestInfo(userRequestInfo, transactionLog: &transactionLog)
		return userRequestInfo
	}

	public func unlockKey(id: String) async throws -> Data? {
		if let dpo = privateKeyObjects[id] {
			return try await dpo.secureArea.unlockKey(id: id)
		}
		return nil
	}
	/// Send response via BLE
	///
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces
	public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: (@Sendable (URL?) -> Void)?) async throws  {
		await handleSelected?(userAccepted, itemsToSend)
		handleSelected = nil
		TransactionLogUtils.setCborTransactionLogResponseInfo(self, transactionLog: &transactionLog)
	}
	
	public func waitForDisconnect() async throws {
		if status == .disconnected { return }
		try await withCheckedThrowingContinuation { c in
			continuationDisconnect = c
		}
	}
}

/// handle events from underlying BLE service
extension BlePresentationService: MdocOfflineDelegate {
	/// BLE transfer changed status
	/// - Parameter newStatus: New status
	public func didChangeStatus(_ newStatus: MdocDataTransfer18013.TransferStatus) {
		Task { @MainActor in
			status = if let st = TransferStatus(rawValue: newStatus.rawValue) { st } else { .error }
			await handleStatusChange(status)
		}
		logger.info("Ble changed status to \(status)")
	}
	/// Transfer finished with error
	/// - Parameter error: The error description
	public func didFinishedWithError(_ error: Error) {
		logger.info("Ble finished with error: \(error)")
		continuationRequest?.resume(throwing: error); continuationRequest = nil
		continuationDisconnect?.resume(throwing: error); continuationDisconnect = nil
	}

	func evaluatePowerOnStatus() {
		if (bleTransferMode == .server && isPeripheralManagerPoweredOn) || (bleTransferMode == .client && isCentralManagerPoweredOn) || (bleTransferMode == .both && isPeripheralManagerPoweredOn && isCentralManagerPoweredOn) {
			continuationPowerOn?.resume(returning: ())
			continuationPowerOn = nil
		}
}

public func didPoweredOn(isPeripheralManager: Bool) {
		logger.info("Ble powered on, isPeripheralManager: \(isPeripheralManager)")
		if isPeripheralManager {
			isPeripheralManagerPoweredOn = true
		} else {
			isCentralManagerPoweredOn = true
		}
		evaluatePowerOnStatus()
	}

	/// BLE device connected
	/// - Parameters:	
	///  - isPeripheral: True if the device connected is a peripheral
	/// - deviceName: The name of the connected device if available
	public func didConnected(isPeripheral: Bool, deviceName: String?) {
		logger.info("Ble device connected, isPeripheral: \(isPeripheral), deviceName: \(deviceName ?? "unknown")")
		if isPeripheral { bleServer = nil }
		else if bleTransferMode == .both { bleTranport = bleServer! }
	}

	/// Received request handler
	/// - Parameters:
	///   - request: Request information
	///   - handleSelected: Callback function to call after user selection of items to send
	public func didReceiveRequest(_ data: Data) {
		logger.info("Ble received request data of length: \(data.count)")
		readBuffer = data
	}

}
