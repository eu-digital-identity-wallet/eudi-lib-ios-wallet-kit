//
//  WalletAppCompatibilityModels.swift
//  EudiWalletKit
//

import Foundation
import JOSESwift
import OpenID4VCI
import Security

public struct IssuerDPoPConstructorParam: @unchecked Sendable {
	public let clientID: String?
	public let expirationDuration: TimeInterval?
	public let aud: String?
	public let jti: String?
	public let jwk: JWK
	public let privateKey: SecKey

	public init(clientID: String?, expirationDuration: TimeInterval?, aud: String?, jti: String?, jwk: JWK, privateKey: SecKey) {
		self.clientID = clientID
		self.expirationDuration = expirationDuration
		self.aud = aud
		self.jti = jti
		self.jwk = jwk
		self.privateKey = privateKey
	}
}

public struct ClientAttestation: Sendable {
	public let wia: String
	public let wiaPop: String

	public init(wia: String, wiaPop: String) {
		self.wia = wia
		self.wiaPop = wiaPop
	}
}

public struct AuthorizedRequestParams: Sendable {
	public let accessToken: String?
	public let refreshToken: String?
	public let cNonce: String?
	public let timeStamp: TimeInterval
	public let dPopNonce: Nonce?

	public init(accessToken: String, refreshToken: String?, cNonce: String?, timeStamp: TimeInterval, dPopNonce: Nonce?) {
		self.accessToken = accessToken
		self.refreshToken = refreshToken
		self.cNonce = cNonce
		self.timeStamp = timeStamp
		self.dPopNonce = dPopNonce
	}
}
