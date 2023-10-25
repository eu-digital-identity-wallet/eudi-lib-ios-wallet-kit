/*
Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Iso18013HolderDemo
Created on 04/10/2023 
*/

import Foundation
import SwiftCBOR
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import SiopOpenID4VP
import JOSESwift
import Logging

class OpenId4VpService: PresentationService {
	var status: TransferStatus = .initialized
	var openid4VPlink: String
	var docs: [DeviceResponse]!
	var iaca: [SecCertificate]!
	var devicePrivateKey: CoseKeyPrivate!
	var logger = Logger(label: "OpenId4VpService")
	var presentationDefinition: PresentationDefinition?
	var resolvedRequestData: ResolvedRequestData?
	var siopOpenId4Vp: SiopOpenID4VP!
	var flow: FlowType

	init(parameters: [String: Any], qrCode: Data) throws {
		self.flow = .openid4vp(qrCode: qrCode)
		guard let wallet = Self.walletConf else {
			throw PresentationSession.makeError(str: "INVALID_WALLET_CONFIGURATION")
		}
		guard let (docs, devicePrivateKey, iaca) = MdocHelpers.initializeData(parameters: parameters) else {
			throw PresentationSession.makeError(str: "MDOC_DATA_NOT_AVAILABLE")
		}
		self.docs = docs; self.devicePrivateKey = devicePrivateKey; self.iaca = iaca
		siopOpenId4Vp = SiopOpenID4VP(walletConfiguration: wallet)
		guard let openid4VPlink = String(data: qrCode, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "QR_DATA_MALFORMED")
		}
		self.openid4VPlink = openid4VPlink
	}
	
	func generateQRCode() async throws -> Data? { nil }
	
	func receiveRequest() async throws -> [String: Any] {
		guard status != .error, let openid4VPURI = URL(string: openid4VPlink) else { throw PresentationSession.makeError(str: "Invalid link \(openid4VPlink)") }
			switch try await siopOpenId4Vp.authorize(url: openid4VPURI)  {
			case .notSecured(data: _):
				throw PresentationSession.makeError(str: "Not secure request received.")
			case let .jwt(request: resolvedRequestData):
				self.resolvedRequestData = resolvedRequestData
				switch resolvedRequestData {
				case let .vpToken(vp):
					self.presentationDefinition = vp.presentationDefinition
					let items = parsePresentationDefinition(vp.presentationDefinition)
					guard let items else { throw PresentationSession.makeError(str: "Invalid presentation definition") }
					return [UserRequestKeys.valid_items_requested.rawValue: items]
				default: throw PresentationSession.makeError(str: "SiopAuthentication request received, not supported yet.")
				}
			}
	}
	
	func sendResponse(userAccepted: Bool, itemsToSend: RequestItems) async throws {
		guard let pd = presentationDefinition, let resolved = resolvedRequestData else {
			throw PresentationSession.makeError(str: "Unexpected error")
		}
		guard userAccepted, itemsToSend.count > 0 else {
			try await SendVpToken(nil, pd, resolved)
			return
		}
		logger.info("Openid4vp request items: \(itemsToSend)")
		guard let (deviceResponse, _, _) = try MdocHelpers.getDeviceResponseToSend(deviceRequest: nil, deviceResponses: docs, selectedItems: itemsToSend) else { throw PresentationSession.makeError(str: "DOCUMENT_ERROR") }
		// Obtain consent
		let vpTokenStr = Data(deviceResponse.toCBOR(options: CBOROptions()).encode()).base64URLEncodedString()
		try await SendVpToken(vpTokenStr, pd, resolved)
	}
	
	fileprivate func SendVpToken(_ vpTokenStr: String?, _ pd: PresentationDefinition, _ resolved: ResolvedRequestData) async throws {
		let consent: ClientConsent = if let vpTokenStr { .vpToken(vpToken: vpTokenStr, presentationSubmission: .init(id: pd.id, definitionID: pd.id, descriptorMap: [])) } else { .negative(message: "Rejected") }
		// Generate a direct post authorisation response
		let response = try AuthorizationResponse(resolvedRequest: resolved, consent: consent, walletOpenId4VPConfig: Self.walletConf!)
		let result: DispatchOutcome = try await siopOpenId4Vp.dispatch(response: response)
		if case let .accepted(url) = result {
			logger.info("Dispatch accepted, return url: \(url?.absoluteString ?? "")")
		} else if case let .rejected(reason) = result {
			logger.info("Dispatch rejected, reason: \(reason)")
			throw PresentationSession.makeError(str: reason)
		}
	}
	
	func parsePresentationDefinition(_ presentationDefinition: PresentationDefinition) -> RequestItems? {
		guard let fieldConstraints = presentationDefinition.inputDescriptors.first?.constraints.fields else { return nil }
		guard let docType = fieldConstraints.first(where: {$0.paths.first == "$.mdoc.doctype" })?.filter?["const"] as? String else { return nil }
		guard let namespace = fieldConstraints.first(where: {$0.paths.first == "$.mdoc.namespace" })?.filter?["const"] as? String else { return nil }
		let requestedFields = fieldConstraints.filter { $0.intentToRetain != nil }.compactMap { $0.paths.first?.replacingOccurrences(of: "$.mdoc.", with: "") }
		return [docType:[namespace:requestedFields]]
	}
	
	static var walletConf: WalletOpenId4VPConfiguration? = {
		let VERIFIER_API = ProcessInfo.processInfo.environment["VERIFIER_API"] ?? "http://localhost:8080"
		let verifierMetaData = PreregisteredClient(clientId: "Verifier", jarSigningAlg: JWSAlgorithm(.RS256), jwkSetSource: WebKeySource.fetchByReference(url: URL(string: "\(VERIFIER_API)/wallet/public-keys.json")!))
		guard let rsaPrivateKey = try? KeyController.generateRSAPrivateKey(), let privateKey = try? KeyController.generateECDHPrivateKey(),
			  let rsaPublicKey = try? KeyController.generateRSAPublicKey(from: rsaPrivateKey) else { return nil }
		guard let rsaJWK = try? RSAPublicKey(publicKey: rsaPublicKey, additionalParameters: ["use": "sig", "kid": UUID().uuidString, "alg": "RS256"]) else { return nil }
		guard let keySet = try? WebKeySet(jwk: rsaJWK) else { return nil }
		var res = WalletOpenId4VPConfiguration(subjectSyntaxTypesSupported: [], preferredSubjectSyntaxType: .jwkThumbprint, decentralizedIdentifier: try! DecentralizedIdentifier(rawValue: "did:example:123"), idTokenTTL: 10 * 60, presentationDefinitionUriSupported: true, signingKey: privateKey, signingKeySet: keySet, supportedClientIdSchemes: [.preregistered(clients: [verifierMetaData.clientId: verifierMetaData])], vpFormatsSupported: [])
		return res
	}()
	
	
}
