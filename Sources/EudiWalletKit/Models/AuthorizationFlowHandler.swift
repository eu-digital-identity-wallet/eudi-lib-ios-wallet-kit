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

import AuthenticationServices
import Foundation

#if canImport(UIKit)
	import UIKit
#endif

/// Handler responsible for presenting the web authorization flow during the OpenID4VCI issuance process.
public protocol AuthorizationFlowHandler: Sendable {
	/// Present `authorizationURL` to the user, run the authorization flow, and return the captured final URI the user
	/// was redirected to.
	/// - Parameters:
	///   - authorizationURL: The endpoint URL where the authorization flow starts from.
	///   - redirectURI: The final URI the user is expected to be redirected to when the flow completes.
	/// - Returns: The final URL that either contains the base redirect URI and the authorization parameters appended to
	///   it, or a presentation request in case of dynamic issuance.
	/// - Throws: Any error thrown here fails the issuance and is propagated to the caller unchanged. The default
	///   implementation throws a ``WalletError`` with code `.userCancelledLogin` if the user cancels the flow.
	func authorize(authorizationURL: URL, redirectURI: URL) async throws -> URL
}

/// Default ``AuthorizationFlowHandler`` that presents the authorization URL in an `ASWebAuthenticationSession`.
@MainActor
class ASWebAuthenticationSessionFlowHandler: AuthorizationFlowHandler {
	private var simpleAuthWebContext: PresentationContext!

	public func authorize(authorizationURL: URL, redirectURI: URL) async throws -> URL {
		#if os(iOS)
			if let scene = UIApplication.shared.connectedScenes.first {
				let activateState = scene.activationState
				if activateState != .foregroundActive { try await Task.sleep(nanoseconds: 1_000_000_000) }
			}
		#endif
		simpleAuthWebContext = PresentationContext()
		let lock = NSLock()
		return try await withCheckedThrowingContinuation { continuation in
			var nillableContinuation: CheckedContinuation<URL, Error>? = continuation
			let authenticationSession = ASWebAuthenticationSession(
				url: authorizationURL,
				callbackURLScheme: redirectURI.scheme!
			) { url, error in
				lock.lock()
				defer { lock.unlock() }
				if let error {
					nillableContinuation?.resume(throwing: WalletError.authRequestFailed(error: error))
					nillableContinuation = nil
					return
				}
				guard let url else {
					nillableContinuation?.resume(
						throwing: WalletError(
							description: "Authorization response does not include a url",
							code: .authorizationFailed
						)
					)
					nillableContinuation = nil
					return
				}
				nillableContinuation?.resume(returning: url)
				nillableContinuation = nil
			}
			authenticationSession.presentationContextProvider = simpleAuthWebContext
			authenticationSession.start()
		}
	}

	final class PresentationContext: NSObject, ASWebAuthenticationPresentationContextProviding {
		func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
			ASPresentationAnchor()
		}
	}
}

extension WalletError {
	public static func authRequestFailed(error: Error) -> WalletError {
		if let wae = error as? ASWebAuthenticationSessionError {
			if wae.code == .canceledLogin { return WalletError(description: "The login has been cancelled.", localizationKey: "login_cancelled", code: .userCancelledLogin, innerError: wae)  }
			else if wae.code == .presentationContextNotProvided { return WalletError(description: "Web authentication presentation context not provided.", code: .authorizationFailed, innerError: wae) }
			else if wae.code == .presentationContextInvalid { return WalletError(description: "Web authentication presentation context invalid.", code: .authorizationFailed, innerError: wae) }
			else { return WalletError(description: wae.localizedDescription, code: .authorizationFailed, innerError: wae) }
		}
		return WalletError(description:"Authorization request failed: \(error.localizedDescription)", code: .authorizationFailed, innerError: error)

	}
}
