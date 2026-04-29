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
import MdocDataModel18013
import MdocSecurity18013

/// Configuration for EudiWallet
public struct EudiWalletConfiguration: Sendable {
    /// The service name for the keychain
	public let serviceName: String
	/// The [access group](https://developer.apple.com/documentation/security/ksecattraccessgroup) that documents are stored in.
	public let accessGroup: String?
    /// Whether user authentication via biometrics or passcode is required before sending user data
	public let userAuthenticationRequired: Bool
	/// Trusted root certificates to validate the reader authentication certificate
	public let trustedReaderRootCertificates: [x5chain]?
	/// Method to perform mdoc authentication (MAC or signature). Defaults to device signature
	public let deviceAuthMethod: DeviceAuthMethod
	/// preferred UI culture for localization of display names. It must be a 2-letter language code. If not set, the system locale is used
	public let uiCulture: String?
	/// If not-nil, logging to the specified log file name will be configured
	public let logFileName: String?
	static let defaultServiceName: String = "eudiw"

	public init(serviceName: String? = nil, accessGroup: String? = nil, userAuthenticationRequired: Bool = false, trustedReaderRootCertificates: [x5chain]? = nil, deviceAuthMethod: DeviceAuthMethod = .deviceSignature, uiCulture: String? = nil, logFileName: String? = nil) {
		self.serviceName = serviceName ?? Self.defaultServiceName
		self.accessGroup = accessGroup
        self.userAuthenticationRequired = userAuthenticationRequired
		self.trustedReaderRootCertificates = trustedReaderRootCertificates
		self.deviceAuthMethod = deviceAuthMethod
		self.uiCulture = uiCulture
		self.logFileName = logFileName
	}
}
