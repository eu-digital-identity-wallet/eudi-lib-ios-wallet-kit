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

import MdocDataModel18013

/// Per document configuration for wallet initiated issuance.
public struct DocumentIssuanceConfiguration: Sendable {
	/// Array of document type identifiers (msoMdoc, sdJwt, or configuration identifier)
	public let docTypeIdentifier: DocTypeIdentifier
	/// Credential options specifying batch size and credential policy. If nil, defaults are fetched from issuer metadata.
	public let credentialOptions: CredentialOptions?
	/// Key options (secure area name and other options) for the document issuing
	public let keyOptions: KeyOptions?
	
	
	public init(docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions? = nil, keyOptions: KeyOptions? = nil) {
		self.docTypeIdentifier = docTypeIdentifier
		self.credentialOptions = credentialOptions
		self.keyOptions = keyOptions
	}
}