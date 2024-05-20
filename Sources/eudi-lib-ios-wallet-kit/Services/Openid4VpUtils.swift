/*
 *  Copyright (c) 2023-2024 European Commission
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import Foundation
import SwiftCBOR
import CryptoKit
/**
 *  Utility class to generate the session transcript for the OpenID4VP protocol.
 *
 *  SessionTranscript = [
 *    DeviceEngagementBytes,
 *    EReaderKeyBytes,
 *    Handover
 *  ]
 *
 *  DeviceEngagementBytes = nil,
 *  EReaderKeyBytes = nil
 *
 *  Handover = OID4VPHandover
 *  OID4VPHandover = [
 *    clientIdHash
 *    responseUriHash
 *    nonce
 *  ]
 *
 *  clientIdHash = Data
 *  responseUriHash = Data
 *
 *  where clientIdHash is the SHA-256 hash of clientIdToHash and responseUriHash is the SHA-256 hash of the responseUriToHash.
 *
 *
 *  clientIdToHash = [clientId, mdocGeneratedNonce]
 *  responseUriToHash = [responseUri, mdocGeneratedNonce]
 *
 *
 *  mdocGeneratedNonce = String
 *  clientId = String
 *  responseUri = String
 *  nonce = String
 *
 */

class Openid4VpUtils {
	
	static func generateSessionTranscript(clientId: String,	responseUri: String, nonce: String,	mdocGeneratedNonce: String) -> [UInt8] {
		let openID4VPHandover = generateOpenId4VpHandover(clientId: clientId, responseUri: responseUri,	nonce: nonce, mdocGeneratedNonce: mdocGeneratedNonce)
		
		let sessionTranscriptBytes = CBOR.encodeArray([CBOR.null, CBOR.null,	openID4VPHandover])
		return sessionTranscriptBytes
	}
	
	static func generateOpenId4VpHandover(clientId: String,	responseUri: String, nonce: String,	mdocGeneratedNonce: String) -> CBOR {
		let clientIdToHash = CBOR.encodeArray([clientId, mdocGeneratedNonce])
		let responseUriToHash = CBOR.encodeArray([responseUri, mdocGeneratedNonce])
		
		let clientIdHash = [UInt8](SHA256.hash(data: clientIdToHash))
		let responseUriHash = [UInt8](SHA256.hash(data: responseUriToHash))
		
		return CBOR.array([.byteString(clientIdHash), .byteString(responseUriHash), .utf8String(nonce)])
	}
	
	static func generateMdocGeneratedNonce() -> String {
		var bytes = [UInt8](repeating: 0, count: 16)
		let result = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
		if result != errSecSuccess {
			logger.warning("Problem generating random bytes with SecRandomCopyBytes")
			bytes = (0 ..< 16).map { _ in UInt8.random(in: UInt8.min ... UInt8.max) }
		}
		return Data(bytes).base64URLEncodedString()
	}
	
	
}

