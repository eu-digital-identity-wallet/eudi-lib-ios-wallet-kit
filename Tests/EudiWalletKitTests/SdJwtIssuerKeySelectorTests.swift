import Testing
import Foundation
import struct JSONWebKey.JWK
@testable import EudiWalletKit

@Suite struct SdJwtIssuerKeySelectorTests {
	let sig = JWK(keyType: .ellipticCurve, publicKeyUse: .signature, keyID: "sig", curve: .p256, x: Data([1]), y: Data([2]))
	let enc = JWK(keyType: .ellipticCurve, publicKeyUse: .encryption, keyID: "enc", curve: .p256, x: Data([3]), y: Data([4]))

	@Test func kidSelectsTheMatchingKey() throws {
		#expect(try SdJwtIssuerKeySelector.select(from: [sig, enc], keyID: "enc", headerKey: nil).keyID == "enc")
	}

	@Test func unknownKidFails() {
		#expect(throws: WalletError.self) { try SdJwtIssuerKeySelector.select(from: [sig, enc], keyID: "other", headerKey: nil) }
	}

	@Test func noKidPicksTheOnlySigningKey() throws {
		#expect(try SdJwtIssuerKeySelector.select(from: [sig, enc], keyID: nil, headerKey: nil).keyID == "sig")
	}

	@Test func noKidWithTwoSigningKeysFails() {
		var second = sig
		second.keyID = "sig2"
		second.x = Data([9])
		#expect(throws: WalletError.self) { try SdJwtIssuerKeySelector.select(from: [sig, second, enc], keyID: nil, headerKey: nil) }
	}

	@Test func headerKeyNarrowsTheChoice() throws {
		var second = sig
		second.keyID = "sig2"
		second.x = Data([9])
		var header = second
		header.keyID = nil
		#expect(try SdJwtIssuerKeySelector.select(from: [sig, second, enc], keyID: nil, headerKey: header).keyID == "sig2")
	}

	@Test func headerKeyNotInMetadataFails() {
		let foreign = JWK(keyType: .ellipticCurve, curve: .p256, x: Data([7]), y: Data([8]))
		#expect(throws: WalletError.self) { try SdJwtIssuerKeySelector.select(from: [sig, enc], keyID: nil, headerKey: foreign) }
	}
}
