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
import SwiftyJSON
import MdocDataModel18013

/// An issuer response must not crash the wallet.
struct CredentialResponseBoundsTests {

	private func makeConfiguration() throws -> CredentialConfiguration {
		CredentialConfiguration(
			configurationIdentifier: try CredentialConfigurationIdentifier(value: "eu.europa.ec.eudi.pid.1"),
			credentialIssuerIdentifier: "https://issuer.example.com",
			vct: "urn:eu:europa:ec:eudi:pid:1",
			supportsAttestationProofType: false,
			supportsJwtProofTypeWithAttestation: false,
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

	private func handle(_ credentials: [Credential], keyCount: Int) async throws -> IssuanceOutcome {
		try await OpenId4VciService.handleCredentialResponse(
			credentials: credentials,
			publicKeys: (0..<keyCount).map { Data([UInt8($0)]) },
			configuration: try makeConfiguration(),
			authorized: try makeAuthorizedRequest(),
			notificationId: nil,
			logger: logger
		)
	}

	@Test func moreStringCredentialsThanKeysThrows() async throws {
		await #expect(throws: WalletError.self) {
			_ = try await handle([.string("a"), .string("b"), .string("c")], keyCount: 2)
		}
	}

	@Test func moreJsonCredentialsThanKeysThrows() async throws {
		let array = JSON([["credential": "a"], ["credential": "b"], ["credential": "c"]])
		await #expect(throws: WalletError.self) {
			_ = try await handle([.json(array)], keyCount: 2)
		}
	}

	@Test func eachCredentialGetsItsKey() async throws {
		let outcome = try await handle([.string("a"), .string("b")], keyCount: 2)
		guard case let .issued(data, _, _, _) = outcome else {
			Issue.record("Expected an issued outcome")
			return
		}
		#expect(data.map(\.publicKey) == [Data([0]), Data([1])])
	}

	@Test func eachCredentialInSeveralArraysGetsItsKey() async throws {
		let first = JSON([["credential": "a"], ["credential": "b"]])
		let second = JSON([["credential": "c"]])
		let outcome = try await handle([.json(first), .string("d"), .json(second)], keyCount: 4)
		guard case let .issued(data, _, _, _) = outcome else {
			Issue.record("Expected an issued outcome")
			return
		}
		#expect(data.map(\.publicKey) == [Data([0]), Data([1]), Data([2]), Data([3])])
	}

	@Test func moreCredentialsInSeveralArraysThanKeysThrows() async throws {
		let first = JSON([["credential": "a"], ["credential": "b"]])
		let second = JSON([["credential": "c"], ["credential": "d"]])
		await #expect(throws: WalletError.self) {
			_ = try await handle([.json(first), .json(second)], keyCount: 2)
		}
	}

	@Test func fewerCredentialsThanKeysIsAccepted() async throws {
		let outcome = try await handle([.string("a")], keyCount: 3)
		guard case let .issued(data, _, _, _) = outcome else {
			Issue.record("Expected an issued outcome")
			return
		}
		#expect(data.map(\.publicKey) == [Data([0])])
	}

	@Test func deferredIssuanceWithoutEndpointThrows() throws {
		let metadata = try JSONDecoder().decode(
			CredentialIssuerMetadata.self,
			from: Data(#"{"credential_issuer":"https://issuer.example.com","credential_endpoint":"https://issuer.example.com/credential","credential_configurations_supported":{}}"#.utf8)
		)
		#expect(throws: WalletError.self) {
			_ = try OpenId4VciService.deferredCredentialEndpoint(of: metadata)
		}
	}
}
