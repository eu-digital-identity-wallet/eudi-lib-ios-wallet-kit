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

public struct AuthorizedRequestParams: Sendable {
	public let accessToken: String?
	public let refreshToken: String?
	public let timeStamp: TimeInterval
	public let tokenType: TokenType?
	public let accessTokenExpiresIn: TimeInterval?
	public let refreshTokenExpiresIn: TimeInterval?

	public init(accessToken: String, refreshToken: String?, timeStamp: TimeInterval, tokenType: TokenType? = .dpop, accessTokenExpiresIn: TimeInterval? = nil, refreshTokenExpiresIn: TimeInterval? = nil) {
		self.accessToken = accessToken
		self.refreshToken = refreshToken
		self.timeStamp = timeStamp
		self.tokenType = tokenType
		self.accessTokenExpiresIn = accessTokenExpiresIn
		self.refreshTokenExpiresIn = refreshTokenExpiresIn
	}

	public init(from authorized: AuthorizedRequest) {
		self.accessToken = authorized.accessToken.accessToken
		self.refreshToken = authorized.refreshToken?.refreshToken
		self.timeStamp = authorized.timeStamp
		self.tokenType = authorized.accessToken.tokenType
		self.accessTokenExpiresIn = authorized.accessToken.expiresIn
		self.refreshTokenExpiresIn = authorized.refreshToken?.expiresIn
	}

	public func toAuthorizedRequest() throws -> AuthorizedRequest {
		guard let accessToken, !accessToken.isEmpty else {
			throw RefreshAuthorizationError.missingAccessToken
		}
		let issuanceAccessToken = try IssuanceAccessToken(accessToken: accessToken, tokenType: tokenType, expiresIn: accessTokenExpiresIn ?? .zero)
		var issuanceRefreshToken: IssuanceRefreshToken?
		if let refreshToken {
			issuanceRefreshToken = try IssuanceRefreshToken(refreshToken: refreshToken, expiresIn: refreshTokenExpiresIn)
		}
		return AuthorizedRequest(accessToken: issuanceAccessToken, refreshToken: issuanceRefreshToken, credentialIdentifiers: nil, timeStamp: timeStamp, dPopNonce: nil, grantType: nil)
	}
}

/// Errors thrown by the refresh-token based credential re-issuance flow.
public enum RefreshAuthorizationError: LocalizedError {
	/// No (or empty) access token was provided; nothing to refresh from.
	case missingAccessToken
	/// The authorization server rejected the refresh token (4xx); a full re-authorization is required.
	case reauthorizationRequired(statusCode: Int, description: String)

	public var errorDescription: String? {
		switch self {
		case .missingAccessToken:
			return "No stored access token available to refresh authorization"
		case .reauthorizationRequired(let statusCode, let description):
			return "Refresh token rejected with status \(statusCode); full re-authorization required. \(description)"
		}
	}
}
