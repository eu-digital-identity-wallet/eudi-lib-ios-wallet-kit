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
import Testing
import MdocDataModel18013
import MdocSecurity18013
import MdocDataTransfer18013
import SwiftCBOR
@testable import EudiWalletKit

private struct ReaderTrust: CertificateTrustValidator {
	var docType: String?
	let trusted: Bool
	func createCertTrustPath(chain: [Data]) async -> [Data]? { trusted ? chain : nil }
	func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) { (trusted, trusted ? nil : "Untrusted reader") }
}

struct BleReaderAuthenticationTests {
	// ISO 18013-5 Annex D request and its matching session transcript.
	static let d51_sessionTranscriptData = Data(base64Encoded: "2BhZAkGD2BhYWKIAYzEuMAGCAdgYWEukAQIgASFYIFqI0YK85fQu+lmUPzM1nS6Klo/yidk+X6REtiQ0MWf+IlggsW6M+Fjdx2kEB7ph1MM4I3qM/PPeaqZy/GClV6oy/GfYGFhLpAECIAEhWCBg4zkjhQQfUUAwUfJBVTHLVt0/mZxxaHATqsZ2i8gYfiJYIOWN64/b6Qf33VNoJFVRo0eW99IhXEQMM5uw97Z77M36gljDkQIPSHMV0QIJYWMBATABBG1kb2MaIAwBYXBwbGljYXRpb24vdm5kLmJsdWV0b290aC5sZS5vb2IwCBsoEos3KCgBAhwBXB5YBGlzby5vcmc6MTgwMTM6ZGV2aWNlZW5nYWdlbWVudG1kb2OiAGMxLjABggHYGFhLpAECIAEhWCBaiNGCvOX0LvpZlD8zNZ0uipaP8onZPl+kRLYkNDFn/iJYILFujPhY3cdpBAe6YdTDOCN6jPzz3mqmcvxgpVeqMvxnWM2RAiVIchWRAgJjcgECEQIEYWMBATAAEQIGYWMBA25mYwBRAgRhYwEBVwAaIB4BYXBwbGljYXRpb24vdm5kLmJsdWV0b290aC5sZS5vb2IwCBsoB4CAvygBAhwCEQfIMv/20m+gvrNN/NVV1II6HBEBA2lzby5vcmc6MTgwMTM6bmZjbmZjAVoXKwFhcHBsaWNhdGlvbi92bmQud2ZhLm5hblcDAQEDIwIAEyT+yacLl6yWhKTjJhdu9bmBxehTPl8AKYz8y8NecAprAgQU")!
	static let request_d411 = Data(base64Encoded: "omd2ZXJzaW9uYzEuMGtkb2NSZXF1ZXN0c4GibGl0ZW1zUmVxdWVzdNgYWJOiZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xpmtmYW1pbHlfbmFtZfVvZG9jdW1lbnRfbnVtYmVy9XJkcml2aW5nX3ByaXZpbGVnZXP1amlzc3VlX2RhdGX1a2V4cGlyeV9kYXRl9Whwb3J0cmFpdPRqcmVhZGVyQXV0aIRDoQEmoRghWQG3MIIBszCCAVigAwIBAgIUdVJxX2rdMj1JNKG6F13JRXVdi1AwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLcmVhZGVyIHJvb3QwHhcNMjAxMDAxMDAwMDAwWhcNMjMxMjMxMDAwMDAwWjARMQ8wDQYDVQQDDAZyZWFkZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT4kS7g+RK2vmg7ovoBIbJjDmAbK2KN/ztE9jlOqpq9vMIUnSnW/xo+CRE1F35cPZxX87+Dl2Hu0Cxk3YKuHTu/o4GIMIGFMBwGA1UdHwQVMBMwEaAPoA2CC2V4YW1wbGUuY29tMB0GA1UdDgQWBBTy38Ssr8XzC0ZPraIL/NUzr14H9TAfBgNVHSMEGDAWgBTPt6iBuupfMrb7kcwpWQxQ36xBbjAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH/BAswCQYHKIGMXQUBBjAKBggqhkjOPQQDAgNJADBGAiEA+56jtob9fqLwI0hY/4MotO/vah73HsSq5OMHIG+SFJMCIQCblPDXOd+oTMop7+1SndSDis/Ytr7iEtxjIMRv64OaNfZYQB80AAaQY8GJE4vc0vYxQnxYlCQRP8nsJs68rKz825aV0o6ZlTvsq8TjCrTvrMg5qB+RWZM9GSUn7pG0Sbt/gL8=")!
	private func transcript() throws -> SessionTranscript {
		guard case let .tagged(_, .byteString(bytes)) = try CBOR.decode(Self.d51_sessionTranscriptData.bytes),
			let cbor = try CBOR.decode(bytes) else { throw WalletError(description: "Bad fixture", code: .internalError) }
		return try SessionTranscript(cbor: cbor)
	}

	@Test func acceptsTrustedReader() async throws {
		try await BlePresentationService.validateReaderAuthentication(deviceRequest: DeviceRequest(data: Self.request_d411.bytes), deviceRequestBytes: Self.request_d411, sessionTranscript: transcript(), trustValidator: ReaderTrust(trusted: true))
	}

	@Test func rejectsUntrustedReader() async throws {
		await #expect(throws: WalletError.self) {
			try await BlePresentationService.validateReaderAuthentication(deviceRequest: DeviceRequest(data: Self.request_d411.bytes), deviceRequestBytes: Self.request_d411, sessionTranscript: transcript(), trustValidator: ReaderTrust(trusted: false))
		}
	}

	@Test func warningPolicyAllowsUntrustedReader() async throws {
		try await BlePresentationService.validateReaderAuthentication(deviceRequest: DeviceRequest(data: Self.request_d411.bytes), deviceRequestBytes: Self.request_d411, sessionTranscript: transcript(), trustValidator: ReaderTrust(trusted: false), readerPolicy: .warning)
	}

	@Test func warningPolicyDoesNotEnforceReaderAuthentication() async throws {
		try await BlePresentationService.validateReaderAuthentication(deviceRequest: DeviceRequest(data: Self.request_d411.bytes), deviceRequestBytes: Self.request_d411, sessionTranscript: SessionTranscript(handOver: .null), trustValidator: ReaderTrust(trusted: true), readerPolicy: .warning)
	}

	@Test func acceptsAbsentAuthentication() async throws {
		let request = DeviceRequest(mdl: [.familyName], agesOver: [], intentToRetain: false)
		try await BlePresentationService.validateReaderAuthentication(deviceRequest: request, deviceRequestBytes: Data(request.encode(options: CBOROptions())), sessionTranscript: transcript(), trustValidator: ReaderTrust(trusted: false))
	}

	@Test func rejectsBadSignatureEvenWithTrustedCertificate() async throws {
		await #expect(throws: (any Error).self) {
			try await BlePresentationService.validateReaderAuthentication(deviceRequest: DeviceRequest(data: Self.request_d411.bytes), deviceRequestBytes: Self.request_d411, sessionTranscript: SessionTranscript(handOver: .null), trustValidator: ReaderTrust(trusted: true))
		}
	}

	@Test func unverifiedCertificateCannotBindRegistration() throws {
		let request = try DeviceRequest(data: Self.request_d411.bytes)
		let chain = request.docRequests[0].readerCertificates
		#expect(BlePresentationService.validatedAccessCertificate(from: ReaderAuthenticationResult(isValidated: false, certificateChain: chain)) == nil)
		#expect(BlePresentationService.validatedAccessCertificate(from: ReaderAuthenticationResult(isValidated: true, certificateChain: chain)) != nil)
		#expect(BlePresentationService.validatedAccessCertificate(from: nil) == nil)
	}

	@Test func unsupportedReaderAuthAllCannotBypassAuthentication() async throws {
		let request = try DeviceRequest(data: Self.request_d411.bytes)
		let unsigned = DeviceRequest(mdl: [.familyName], agesOver: [], intentToRetain: false)
		let auth = try #require(request.docRequests[0].readerAuthRawCBOR)
		let authAllRequest = try DeviceRequest(cbor: ["version": "1.1", "docRequests": .array(unsigned.docRequests.map { $0.toCBOR(options: CBOROptions()) }), "readerAuthAll": .array([auth])])
		await #expect(throws: WalletError.self) {
			try await BlePresentationService.validateReaderAuthentication(deviceRequest: authAllRequest, deviceRequestBytes: Data(authAllRequest.encode(options: CBOROptions())), sessionTranscript: transcript(), trustValidator: ReaderTrust(trusted: true))
		}
	}

	@Test(arguments: [CBOR.null, CBOR.byteString([]), CBOR.map([:])])
	func rejectsMalformedReaderAuthAll(_ value: CBOR) async throws {
		let unsigned = DeviceRequest(mdl: [.familyName], agesOver: [], intentToRetain: false)
		let raw: CBOR = ["version": "1.1", "docRequests": .array(unsigned.docRequests.map { $0.toCBOR(options: CBOROptions()) }), "readerAuthAll": value]
		let request = try DeviceRequest(cbor: raw)
		#expect(request.readerAuthAllRawCBOR == nil)
		await #expect(throws: WalletError.self) {
			try await BlePresentationService.validateReaderAuthentication(deviceRequest: request, deviceRequestBytes: Data(raw.encode()), sessionTranscript: transcript(), trustValidator: ReaderTrust(trusted: false))
		}
	}

	@Test func duplicateDocTypesCannotHideFailedAuthentication() async throws {
		let request = try DeviceRequest(data: Self.request_d411.bytes)
		var signed = request.docRequests[0].toCBOR(options: CBOROptions())
		// Remove authentication from a second request of the same type. A docType-keyed
		// summary would replace the first reader's failed result with this unsigned one.
		guard case var .map(unsigned) = signed else { return }
		unsigned["readerAuth"] = nil
		signed = .map(unsigned)
		let duplicated = try DeviceRequest(cbor: ["version": "1.0", "docRequests": .array([request.docRequests[0].toCBOR(options: CBOROptions()), signed])])
		await #expect(throws: WalletError.self) {
			try await BlePresentationService.validateReaderAuthentication(deviceRequest: duplicated, deviceRequestBytes: Data(duplicated.encode(options: CBOROptions())), sessionTranscript: transcript(), trustValidator: ReaderTrust(trusted: false))
		}
	}
}
