import Foundation
import Testing
import WalletStorage
@testable import EudiWalletKit

@Suite("Deferred issuance interval")
struct DeferredIssuanceIntervalTests {
	private static func document(model: String, status: WalletStorage.DocumentStatus = .deferred) -> WalletStorage.Document {
		WalletStorage.Document(docType: "eu.europa.ec.eudi.pid.1", docDataFormat: .sdjwt, data: Data(model.utf8), docKeyInfo: nil, createdAt: nil, metadata: nil, displayName: nil, status: status)
	}

	private static let model = """
	{"deferredCredentialEndpoint": "https://issuer.example.com/deferred", "transactionId": {"value": "tx-1"}, "publicKeys": [], "timeStamp": 0
	"""

	@Test("a deferred document returns the interval of the issuer")
	func returnsInterval() {
		#expect(Self.document(model: Self.model + #", "interval": 5}"#).deferredIssuanceInterval == 5)
	}

	@Test("a deferred document stored without an interval returns nil")
	func olderDocumentHasNoInterval() {
		#expect(Self.document(model: Self.model + "}").deferredIssuanceInterval == nil)
	}

	@Test("a document that is not deferred returns nil")
	func issuedDocumentHasNoInterval() {
		#expect(Self.document(model: Self.model + #", "interval": 5}"#, status: .issued).deferredIssuanceInterval == nil)
	}
}
