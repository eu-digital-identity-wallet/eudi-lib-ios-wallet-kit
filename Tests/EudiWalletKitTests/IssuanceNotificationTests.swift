/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Testing
@testable import EudiWalletKit
import Foundation
import OpenID4VCI
import MdocDataModel18013
import WalletStorage
import MdocSecurity18013
import SwiftyJSON
import SwiftCBOR
import X509

struct IssuanceNotificationTests {

	private func makeVciService(
		storageService: any DataStorageService = TestDataStorageService(),
		issuerURL: String = "https://dev.issuer.eudiw.dev"
	) throws -> OpenId4VciService {
		let networking = TestNetworking(metadata: try makeSdJwtIssuerMetadata(forResource: "sjwt-pid", issuerURL: issuerURL))
		let storage = StorageManager(storageService: storageService)
		let config = OpenId4VciConfiguration(credentialIssuerURL: issuerURL, requirePAR: true, requireDpop: true)
		return try OpenId4VciService(uiCulture: nil, config: config, networking: networking, storage: storage, storageService: storageService)
	}

	private func makeIssuedDocument() throws -> (data: Data, publicKey: Data) {
		let raw = Data(name: "sjwt-pid", ext: "txt", from: Bundle.module)!
		guard let serialized = String(data: raw, encoding: .utf8) else {
			throw NSError(domain: "TestFixture", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot decode sjwt-pid.txt"])
		}
		let (_, payload, _) = SdJwtUtils.extractJWTParts(serialized)
		guard let payloadData = Data(base64URLEncoded: payload),
			  let payloadJson = try? JSON(data: payloadData) else {
			throw NSError(domain: "TestFixture", code: 2, userInfo: [NSLocalizedDescriptionKey: "Cannot decode SD-JWT payload"])
		}
		let jwk = payloadJson["cnf"]["jwk"]
		guard let crvName = jwk["crv"].string else {
			throw NSError(domain: "TestFixture", code: 3, userInfo: [NSLocalizedDescriptionKey: "Missing crv"])
		}
		guard let crv = MdocDataModel18013.CoseEcCurve(crvName: crvName) else {
			throw NSError(domain: "TestFixture", code: 4, userInfo: [NSLocalizedDescriptionKey: "Unknown curve: \(crvName)"])
		}
		guard let xStr = jwk["x"].string, let yStr = jwk["y"].string,
			  let x = Data(base64URLEncoded: xStr), let y = Data(base64URLEncoded: yStr) else {
			throw NSError(domain: "TestFixture", code: 5, userInfo: [NSLocalizedDescriptionKey: "Missing x/y coordinates"])
		}
		let coseKey = CoseKey(x: [UInt8](x), y: [UInt8](y), crv: crv)
		return (raw, Data(coseKey.encode(options: CBOROptions())))
	}

	private func makeCredentialConfiguration() throws -> CredentialConfiguration {
		CredentialConfiguration(
			configurationIdentifier: try CredentialConfigurationIdentifier(value: "eu.europa.ec.eudi.pid.1"),
			credentialIssuerIdentifier: "https://dev.issuer.eudiw.dev",
			vct: "urn:eu:europa:ec:eudi:pid:1",
			supportsAttestationProofType: false,
			supportsJwtProofTypeWithAttestation: false,
			supportsJwtProofTypeWithoutAttestation: true,
			credentialSigningAlgValuesSupported: ["ES256"],
			dpopSigningAlgValuesSupported: nil,
			clientAttestationPopSigningAlgValuesSupported: nil,
			issuerDisplay: [],
			display: [],
			claims: [],
			format: .sdjwt,
			defaultCredentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1)
		)
	}

	private func makeAuthorizedRequest() throws -> AuthorizedRequest {
		AuthorizedRequest(
			accessToken: try IssuanceAccessToken(accessToken: "test-token", tokenType: .bearer),
			refreshToken: nil,
			credentialIdentifiers: nil,
			timeStamp: 0,
			dPopNonce: nil,
			grantType: nil
		)
	}

	private func makeIssuanceOutcome(notificationId: String?) throws -> (IssuanceOutcome, IssueRequest) {
		SecureAreaRegistry.shared.register(secureArea: SoftwareSecureArea.create(storage: InMemorySecureKeyStorage()))
		let (docData, pubKeyData) = try makeIssuedDocument()
		let outcome = IssuanceOutcome.issued(
			[(data: docData, publicKey: pubKeyData)],
			try makeCredentialConfiguration(),
			try makeAuthorizedRequest(),
			notificationId: notificationId
		)
		let issueReq = try IssueRequest(
			id: UUID().uuidString,
			credentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1)
		)
		return (outcome, issueReq)
	}

	private func awaitNotification(from spy: SpyIssuer, timeout seconds: Double = 2) async throws -> NotificationObject {
		let signal = spy.signal
		return try await withThrowingTaskGroup(of: NotificationObject.self) { group in
			group.addTask { await signal.wait() }
			group.addTask {
				try await Task.sleep(for: .seconds(seconds))
				throw CancellationError()
			}
			let result = try await group.next()!
			group.cancelAll()
			return result
		}
	}

	private func makeSdJwtIssuerMetadata(forResource resourceName: String, issuerURL: String) throws -> Data {
		guard let raw = Data(name: resourceName, ext: "txt", from: Bundle.module),
			  let serialized = String(data: raw, encoding: .utf8) else {
			throw NSError(domain: "TestFixture", code: 6, userInfo: [NSLocalizedDescriptionKey: "Cannot load \(resourceName).txt"])
		}
		let (header, _, _) = SdJwtUtils.extractJWTParts(serialized)
		guard let headerData = Data(base64URLEncoded: header),
			  let headerJson = try? JSON(data: headerData),
			  let certificateBase64 = headerJson["x5c"].array?.first?.string,
			  let certificateData = Data(base64Encoded: certificateBase64) else {
			throw NSError(domain: "TestFixture", code: 7, userInfo: [NSLocalizedDescriptionKey: "Cannot extract x5c from \(resourceName)"])
		}
		let keyData = Data(try X509.Certificate(derEncoded: [UInt8](certificateData)).publicKey.subjectPublicKeyInfoBytes)
		let metadata: [String: Any] = [
			"issuer": issuerURL,
			"jwks": ["keys": [["use": "sig", "kty": "EC", "crv": "P-256", "x": keyData.base64EncodedString(), "y": ""]]]
		]
		return try JSONSerialization.data(withJSONObject: metadata)
	}

	@Test("sends credentialAccepted after storage succeeds when notificationId is present")
	func testSendsAcceptedNotificationOnStorageSuccess() async throws {
		let spy = SpyIssuer()
		let service = try makeVciService()
		let (outcome, issueReq) = try makeIssuanceOutcome(notificationId: "test-notif-id")

		_ = try await service.finalizeIssuing(
			issueOutcome: outcome,
			docType: "urn:eu:europa:ec:eudi:pid:1",
			format: .sdjwt,
			issueReq: issueReq,
			deleteId: nil,
			issuer: spy
		)

		let notification = try await awaitNotification(from: spy)
		#expect(notification.event == .credentialAccepted)
		#expect(notification.id.value == "test-notif-id")
	}

	@Test("sends credentialFailure when storage fails and notificationId is present")
	func testSendsFailureNotificationOnStorageError() async throws {
		let spy = SpyIssuer()
		let storeError = NSError(domain: "TestStorage", code: 1, userInfo: [NSLocalizedDescriptionKey: "disk full"])
		let service = try makeVciService(storageService: FailingStorageService(saveError: storeError))
		let (outcome, issueReq) = try makeIssuanceOutcome(notificationId: "test-notif-id")

		await #expect(throws: (any Error).self) {
			_ = try await service.finalizeIssuing(
				issueOutcome: outcome,
				docType: "urn:eu:europa:ec:eudi:pid:1",
				format: .sdjwt,
				issueReq: issueReq,
				deleteId: nil,
				issuer: spy
			)
		}

		let notification = try await awaitNotification(from: spy)
		#expect(notification.event == .credentialFailure)
		#expect(notification.id.value == "test-notif-id")
		#expect(notification.eventDescription == storeError.localizedDescription)
	}

	@Test("does not notify issuer when notificationId is absent")
	func testNoNotificationWhenNotificationIdAbsent() async throws {
		let spy = SpyIssuer()
		let service = try makeVciService()
		let (outcome, issueReq) = try makeIssuanceOutcome(notificationId: nil)

		_ = try await service.finalizeIssuing(
			issueOutcome: outcome,
			docType: "urn:eu:europa:ec:eudi:pid:1",
			format: .sdjwt,
			issueReq: issueReq,
			deleteId: nil,
			issuer: spy
		)

		let count = await spy.notifyCallCount
		#expect(count == 0)
	}

	@Test("issuance succeeds even when notification call throws")
	func testIssuanceSucceedsWhenNotificationThrows() async throws {
		let spy = SpyIssuer(notifyError: NSError(domain: "TestNetwork", code: -1, userInfo: [NSLocalizedDescriptionKey: "network timeout"]))
		let service = try makeVciService()
		let (outcome, issueReq) = try makeIssuanceOutcome(notificationId: "test-notif-id")

		let document = try await service.finalizeIssuing(
			issueOutcome: outcome,
			docType: "urn:eu:europa:ec:eudi:pid:1",
			format: .sdjwt,
			issueReq: issueReq,
			deleteId: nil,
			issuer: spy
		)

		_ = try await awaitNotification(from: spy)
		#expect(document.id == issueReq.id)
		#expect(await spy.notifyCallCount == 1)
	}
}

actor NotificationSignal {
	private var stored: NotificationObject?
	private var waiter: CheckedContinuation<NotificationObject, Never>?

	func signal(_ notification: NotificationObject) {
		stored = notification
		waiter?.resume(returning: notification)
		waiter = nil
	}

	func wait() async -> NotificationObject {
		if let stored { self.stored = nil; return stored }
		return await withCheckedContinuation { waiter = $0 }
	}
}

actor SpyIssuer: IssuerType {
	var notifyCallCount = 0
	var notifyError: Error?
	let signal: NotificationSignal

	init(signal: NotificationSignal = NotificationSignal(), notifyError: Error? = nil) {
		self.signal = signal
		self.notifyError = notifyError
	}

	func notify(authorizedRequest: AuthorizedRequest, notification: NotificationObject, dPopNonce: Nonce?) async throws {
		notifyCallCount += 1
		await signal.signal(notification)
		if let error = notifyError { throw error }
	}

	func setDeferredResponseEncryptionSpec(_ spec: IssuanceResponseEncryptionSpec?) async {}
	func prepareAuthorizationRequest(credentialOffer: CredentialOffer) async throws -> AuthorizationRequested { fatalError("stub") }
	func authorizeWithPreAuthorizationCode(credentialOffer: CredentialOffer, authorizationCode: IssuanceAuthorization, client: Client, transactionCode: String?, authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest) async throws -> AuthorizedRequest { fatalError("stub") }
	func authorizeWithAuthorizationCode(serverState: String, request: AuthorizationRequested, authorizationCode: AuthorizationCode, authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest, grant: Grants) async throws -> AuthorizedRequest { fatalError("stub") }
	func requestCredential(request: AuthorizedRequest, bindingKeys: [BindingKey], requestPayload: IssuanceRequestPayload, responseEncryptionSpecProvider: @Sendable (CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?) async throws -> SubmittedRequest { fatalError("stub") }
	func requestDeferredCredential(request: AuthorizedRequest, transactionId: TransactionId, dPopNonce: Nonce?) async throws -> DeferredCredentialIssuanceResponse { fatalError("stub") }
	func refresh(clientId: String, authorizedRequest: AuthorizedRequest, dPopNonce: Nonce?) async throws -> AuthorizedRequest { fatalError("stub") }
	func refresh(client: Client, authorizedRequest: AuthorizedRequest, dPopNonce: Nonce?) async throws -> AuthorizedRequest { fatalError("stub") }
}

actor FailingStorageService: DataStorageService {
	let saveError: Error
	init(saveError: Error = NSError(domain: "TestStorage", code: 1, userInfo: [NSLocalizedDescriptionKey: "disk full"])) {
		self.saveError = saveError
	}
	func loadDocument(id: String, status: DocumentStatus) async throws -> WalletStorage.Document? { nil }
	func loadDocumentMetadata(id: String) async throws -> DocMetadata? { nil }
	func loadDocuments(status: DocumentStatus) async throws -> [WalletStorage.Document]? { [] }
	func saveDocument(_ document: WalletStorage.Document, batch: [WalletStorage.Document]?, allowOverwrite: Bool) async throws { throw saveError }
	func deleteDocument(id: String, status: DocumentStatus) async throws {}
	func deleteDocuments(status: DocumentStatus) async throws {}
	func deleteDocumentCredential(id: String, index: Int) async throws {}
}
