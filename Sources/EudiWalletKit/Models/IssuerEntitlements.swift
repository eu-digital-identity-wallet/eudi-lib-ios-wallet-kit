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

/// Provider entitlement URIs carried in a registration certificate (ETSI TS 119 475 / TS5).
enum IssuerEntitlements {
	private static let base = "https://uri.etsi.org/19475/Entitlement"
	static let pid = "\(base)/PID_Provider"
	static let qeaa = "\(base)/QEAA_Provider"
	static let pubEaa = "\(base)/PUB_EAA_Provider"
	static let nonQEaa = "\(base)/Non_Q_EAA_Provider"
}

/// The provider role required by an offered attestation.
/// PID offers require PID registration. Other offers accept any EAA provider role:
/// the registrar's role need not match the wallet's local attestation classification.
enum EntitlementRequirement: CaseIterable, Hashable {
	case pidProvider
	case eaaProvider

	var acceptedEntitlements: [String] {
		switch self {
		case .pidProvider: [IssuerEntitlements.pid]
		case .eaaProvider: [IssuerEntitlements.qeaa, IssuerEntitlements.pubEaa, IssuerEntitlements.nonQEaa]
		}
	}

	func isMetBy(_ entitlements: [String]) -> Bool {
		entitlements.contains { entitlement in acceptedEntitlements.contains(entitlement) }
	}
}

extension WrpRegistrationPolicy {
	/// Returns the distinct provider requirements this registration does not satisfy.
	/// Classifies each offer using its mdoc type and every SD-JWT VC type. Missing types,
	/// or an absent PID classification, count as non-PID offers. Empty offers have no requirements.
	func findUnmetEntitlements(
		offered: [PolicyCredentialMeta],
		isPid: (String) -> Bool
	) -> Set<EntitlementRequirement> {
		Set(offered.map { meta in
			let identifiers = [meta.doctypeValue].compactMap { $0 } + (meta.vctValues ?? [])
			return identifiers.contains(where: isPid) ? EntitlementRequirement.pidProvider : .eaaProvider
		}.filter { !$0.isMetBy(entitlements ?? []) })
	}
}
