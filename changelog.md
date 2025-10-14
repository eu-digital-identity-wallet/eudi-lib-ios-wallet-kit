## v0.16.2
- **Feature**: Added DPoP configuration support 
  - Added `useDpopIfSupported` property to `OpenId4VCIConfiguration` to enable/disable DPoP usage (default: `true`)
  - Conditionally use DPoP constructor based on the `useDpopIfSupported` configuration setting
  - DPoP is now only used when both supported by the issuer and enabled in the configuration


## v0.16.1
- Fix deferred issuance bug

## v0.16.0
- **Breaking change**: Updated OpenID4VCI to version 0.16.0 with support for OpenID4VCI v1.0 specification
  - Updated `eudi-lib-ios-openid4vci-swift` from version 0.7.6 to 0.16.0
  - Implemented changes for OpenID4VCI v1.0 specification compatibility:
    - Updated deferred credential issuance handling to support new API with separate `transactionId` and `interval` parameters
    - Enhanced credential metadata access through new `ConfigurationCredentialMetadata` structure
    - Added support for new `issuanceStillPending` case in deferred credential flows
    - Improved error handling and logging for deferred credential scenarios
- Updated `eudi-lib-sdjwt-swift` from version 0.8.0 to 0.9.1

## v0.15.0
- Update dependency versions
  - Updated `eudi-lib-ios-iso18013-data-transfer` from version 0.8.0 to 0.8.1
  - Updated `eudi-lib-ios-siop-openid4vp-swift` from version 0.17.3 to 0.17.5
- Enhanced CBOR document validation
  - Perform CBOR document validation logic in `EudiWallet`, `validateIssuedDocuments` method: 
  	- CBOR element digest values are compared against the digest values provided in the issuer-signed Mobile Security Object (MSO) section of the document to ensure integrity and authenticity.
	- MSO Signature is validated.
	- MSO Validity info dates are validated.
	- Doc type in MSO is the same as the doc type of the issued document.
  

## v0.14.9
- feat: introduce OpenID4VP configuration and refactor related classes
  - Added new `OpenId4VpConfiguration` model with support for different client identifier schemes
  - Introduced `ClientIdScheme` enum supporting preregistered clients, X.509 certificate validation (SAN DNS and hash), and redirect URI validation
  - **Breaking change**: Refactored `EudiWallet` initialization and property to use a `OpenId4VpConfiguration` parameter instead of separate `verifierApiUri` and `verifierLegalName` parameters, for example: `wallet.openID4VpConfig = OpenId4VpConfiguration(clientIdSchemes: [.x509SanDns])`	
  - Added convenience initializer for `PreregisteredClient` from SiopOpenID4VP library
  - Updated related services to work with the new configuration structure

## v0.14.7
- Fix: Throw error if one of the requested doc types is not present and credentialSets is nil

## v0.14.6
- Error reason [provided](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-wallet-kit/documentation/eudiwalletkit/presentationsession/uierror) when OpenID4VP response is rejected

## v0.14.5
- Fix CBOR log document claim decoding logic

## v0.14.4
- Fix transaction logs decoding

## v0.14.3
- Update eudi-lib-ios-siop-openid4vp-swift dependency to version [0.17.2](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift/releases/tag/v0.17.2)

## v0.14.2
- Update eudi-lib-ios-siop-openid4vp-swift to 0.17.0 and enhance certificate verification

## v0.14.1
- Fixes bug for sd-jwt documents array values not transfered with online presentation e.g. nationalities for PID

## v0.14.0
- Updated OpenID4VP library to version [v0.16.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift/releases/tag/v0.16.0) and adjusted wallet kit accordingly.

## v0.13.5
- Update eudi-lib-ios-openid4vci-swift to [0.15.4](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.15.4)
- Added  property `var credentialPocily: CredentialPolicy` to `DocClaimsDecodable`
- fix for removing port from URL (issue #215)

## v0.13.4
- Update the eudi-lib-ios-siop-openid4vp-swift dependency to version 0.15.1 (JARM fix)

## v0.13.3
- Updated eudi-lib-ios-siop-openid4vp-swift library to version [v0.15.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift/releases/tag/v0.15.0)
- Updated eudi-lib-ios-openid4vci-swift library to version [v0.15.2](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.15.2)

- **Breaking change**: Removed  `EudiWallet` property`verifierRedirectUri`

## v0.13.2

### Error Handling Improvements:
- **Improved WalletError structure**: Refactored `WalletError` from enum to struct with property to support localization: `public let localizationKey: String?`.
- **Enhanced error logging**: Added `logger.error` statements before all `throw` statements across the wallet codebase to improve debugging capabilities.

## v0.13.1
- Fix for presentations based on DCQL query

## v0.13.0
- Fixed failure to issue documents with credential offer when the authorization server defined in the offer uses DPoP.
- Fixed credential offer issuance to use batch size passed to `issueDocumentsByOfferUrl`.

## v0.12.9
- Updated [eudi-lib-sdjwt-swift](https://github.com/eu-digital-identity-wallet/eudi-lib-sdjwt-swift) library to version v0.7.2
- Updated dPoP constructor logic and added RS256 algorithm

## v0.12.8

### Changes:
- `DocClaimsDecodable` has a new property `var credentialsUsageCounts: CredentialsUsageCounts?`
This property provides information about the number of remaining presentations available for a document, based on its credential policy. It is useful for documents issued with a one-time use policy, where it returns the number of remaining presentations available. For documents with a rotate-use policy, it returns nil as there's no usage limit. 
- Deprecated `getCredentialsUsageCount` method in `EudiWallet`. Use the new `credentialsUsageCounts` property instead.

#### Performance Improvements:
- **Configurable metadata caching**: Added `cacheIssuerMetadata: Bool` parameter to `OpenId4VCIConfiguration` (defaults to `true`). This flag controls whether issuer metadata should be cached in memory during the session.

### Bug Fixes:
- `DocClaimsDecodable` models are backed by classes instead of structs to ensure proper reference semantics. This allows the `credentialsUsageCounts` property to be updated correctly without requiring a full reload of the document claims.
- Fixed issue with getting issuer metadata from wrong server when a url offer is used with different server than the default one.

## v0.12.7

#### DPoP updates
- Library `eudi-lib-ios-openid4vci-swift` has been updated to version 0.15.1
- DPoP constructor is always passed.

#### Performance Improvements:
- **Issuer metadata caching**: Added caching to `OpenId4VCIService.getIssuerMetadata` to improve performance by storing successful issuer metadata results in memory and avoiding redundant network requests during the same session. The cache is automatically cleared after changing issuerUrl.

#### Bug fixes: 
 - When the `getCredentialsUsageCount` method is called, if the remaining count is 0, the `validUntil` property of the credential is now correctly set to `nil`.

#### Breaking Changes:

The `getDefaultKeyOptions` and `issueDocument` method signatures have been updated to accept a single `DocTypeIdentifier` parameter instead of separate `docType`, `scope`, and `identifier` parameters for improved type safety and API consistency.
The `getDefaultKeyOptions` method queries the issuer to retrieve the recommended key configuration for a specific document type identifier.
The returned KeyOptions can be used when issuing documents with `issueDocument`.

#### Before:
```swift
let keyOptions = try await wallet.getDefaultKeyOptions(docType, scope: scope, identifier: identifier)
let document = try await wallet.issueDocument(docType: docType, scope: scope, identifier: identifier, keyOptions: keyOptions)
```

#### After:
```swift
let keyOptions = try await wallet.getDefaultKeyOptions(.msoMdoc("org.iso.18013.5.1.mDL"))
let document = try await wallet.issueDocument(.msoMdoc("org.iso.18013.5.1.mDL"), keyOptions: keyOptions)
// or
let keyOptions = try await wallet.getDefaultKeyOptions(.sdJwt(vct: "urn:eudi:pid:1"))
let document = try await wallet.issueDocument(.sdJwt(vct: "urn:eudi:pid:1"), keyOptions: keyOptions)
// or
let keyOptions = try await wallet.getDefaultKeyOptions(.configurationIdentifier("eu.europa.ec.eudi.cor_mdoc"))
let document = try await wallet.issueDocument(.configurationIdentifier("eu.europa.ec.eudi.cor_mdoc"), keyOptions: keyOptions)
```

## v0.12.6
### Networking abstraction and protocol improvements

- **EudiWallet initialization parameter change**: The `urlSession` parameter has been replaced with `networking` parameter
  - Old: `urlSession: URLSession? = nil`
  - New: `networking: (any NetworkingProtocol)? = nil`
  - This allows for custom networking implementations while maintaining URLSession compatibility

#### New NetworkingProtocol
- Added `NetworkingProtocol` that abstracts network operations
  - Provides `data(from url: URL)` and `data(for request: URLRequest)` methods
  - `URLSession` conforms to `NetworkingProtocol` by default for backward compatibility

#### Internal networking improvements
- Split networking into separate VCI and VP clients:
  - `networkingVci: OpenID4VCINetworking` - For OpenID4VCI operations
  - `networkingVp: OpenID4VPNetworking` - For OpenID4VP operations
- Both networking clients wrap the provided `NetworkingProtocol` implementation

### `SecureArea` Protocol Improvements
- Added property `static var supportedEcCurves: [CoseEcCurve]`

### Bug Fixes
- Fix for issue #187
- Fix for issue #190
- Fix for issue #195
- Fix for issue: Attestation with 0 instances still triggers share flow
- Fix for issue: Expiration date shown despite no available attestations
- Fix for issue: When there is no matching attestation for BLE transfer, the QR code is still displayed.


## v0.12.5
-- Fixed redirect_uri clientId scheme handling

## v0.12.4
### `EudiWallet` property addition
- Added `verifierRedirectUri: String?` property to `EudiWallet`.
  - This property stores the OpenID4VP verifier redirect URI, used for redirectUri clients in OpenID4VP flows.

### Fix to delete one-time credentials for presented documents only
- Updated the logic to ensure that only one-time credentials for documents that have been presented are deleted.

### Fix to `issueDocumentsByOfferUrl` crash
- When multiple documents were issued many times the 'Fatal error: Unexpectedly found nil while unwrapping an Optional value' occurred.

## v0.12.3
 - Use exact versions for dependencies

## v0.12.2
 ### Modified issueDocumentsByOfferUrl method

 ```swift
	/// Issue documents by offer URI.
	/// - Parameters:
	///   - offerUri: url with offer
	///   - docTypes: offered doc models available to be issued. Contains key options (secure are name and other options)
	///   - txCodeValue: Transaction code given to user (if available)
	///   - promptMessage: prompt message for biometric authentication (optional)
	/// - Returns: Array of issued and stored documents
	public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], txCodeValue: String? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
 ```

 Example usage:

  ```swift
 // When resolving an offer, key options are now included
 let offer = try await wallet.resolveOfferUrlDocTypes(uriOffer: offerUrl)
 for docModel in offer.docModels {
	// use recommended key options or modify them
	 let docTypes = offer.docModels.map { $0.copy(keyOptions: KeyOptions(credentialPolicy: .oneTimeUse, batchSize: 2))
     // Issue with optimal settings
     let newDocs = try await wallet.issueDocumentsByOfferUrl(offerUri: offerUrl, docTypes: docTypes, txCodeValue: txCode)
 }
 ```

### `OfferedDocModel` struct enhancements

 #### Added properties:
 - `identifier: String?` - Issuer configuration identifier for the credential
 - `keyOptions: KeyOptions` - Default key options (batch size and credential policy) recommended by the issuer

 #### Updated computed property:
 - `docTypeOrVctOrScope` renamed to `docTypeOrVctOrScope` - Now returns docType, vct, or scope in priority order



## v0.12.1

 ### `EudiWallet` added method: `public func getCredentialsUsageCount(id: String) async throws -> CredentialsUsageCounts?`
 Gets a document's remaining credentials, available for presentation count
 This method retrieves usage count information for a specific document based on its credential policy.
 For documents issued with a one-time use policy, it returns the number of remaining presentations
 available. For documents with a rotate-use policy, it returns nil as there's no usage limit.

 ```swift
 if let usageCounts = try await wallet.getCredentialsUsageCount(id: documentId) {
     print("Remaining presentations: \(usageCounts.remaining) out of \(usageCounts.total)")
 } else {
     print("Document has unlimited presentations (rotate-use policy)")
 }
 ```

 ### `EudiWallet` added method: `public func getDefaultKeyOptions(_ docType: String?, scope: String?, identifier: String?) async throws -> KeyOptions`
 Get default key options (batch-size and credential policy) for a document type from the issuer.
 This method queries the issuer to retrieve the recommended key configuration for a specific document type,
 scope, or identifier. The returned KeyOptions can be used when issuing documents.

 ```swift
 let keyOptions = try await wallet.getDefaultKeyOptions(docType, scope: scope, identifier: identifier)
 let document = try await wallet.issueDocument(docType: docType, scope: scope, identifier: identifier, keyOptions: keyOptions)
 ```

 ### `OfferedDocModel` removed method: `getRemainingCredentialsCount`


## v0.12.0

### Batch issuance support
To issue multiple credentials for a document, specify the `keyOptions` parameter in the `issueDocument` method. This allows to set the `credentialPolicy` and `batchSize` options.

Example usage:
```swift
try await wallet.issueDocument(docType: nil, scope: nil, identifier: identifier, keyOptions: KeyOptions(credentialPolicy: .oneTimeUse, batchSize: 10))
```

#### Additional method
``` swift
/// Get the remaining presentations count for a document.
/// Returns: Remaining presentations count (if one-time use policy was used to issue the document, otherwise nil)
public func getRemainingCredentialsCount(id: String) async throws -> Int?
```

### SecureArea Protocol: Batch-Oriented API Changes

The `SecureArea` protocol was refactored to support batch-oriented key management and cryptographic operations. This change introduces methods for handling multiple keys at once. This affects implementors of the `SecureArea` protocol.

#### 1. Batch Operations Added

- **Key Creation:**
  - `createKeyBatch(id: String, keyOptions: KeyOptions?) async throws -> [CoseKey]`
    - Creates a batch of keys and returns their public keys.

- **Key Deletion:**
  - `deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) async throws`
    - Deletes a batch of keys starting from a specific index.
  - `deleteKeyInfo(id: String) async throws`
    - Deletes key metadata for a given batch.

- **Signature and Key Agreement:**
  - `signature(id: String, index: Int, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?) async throws -> Data`
    - Computes a signature using a specific key in the batch.
  - `keyAgreement(id: String, index: Int, publicKey: CoseKey, unlockData: Data?) async throws -> SharedSecret`
    - Performs key agreement with a specific key in the batch.

- **Key Info:**
  - `getKeyBatchInfo(id: String) async throws -> KeyBatchInfo`
    - Returns information about a batch of keys.

- **Default Algorithm:**
  - `defaultSigningAlgorithm(ecCurve: CoseEcCurve) -> SigningAlgorithm`
    - Returns the default signing algorithm for a given curve.

#### 2. Single-Key Methods Removed

- Single-key methods `createKey`, `deleteKey`, and `getKeyInfo` were removed.


## v0.11.3
- Display "Unidentified Relying Party" when reader authentication is disabled.
- Fix transactions log for verifications with DCQL queries

## v0.11.2
- Update eudi-lib-ios-siop-openid4vp-swift package dependency to version 0.11.0
- DCQL query language support

## v0.11.1
- Package updates

## v0.11.0
- Bug fixes

## v0.10.9
- Updated eudi-lib-ios-siop-openid4vp-swift library to (v0.10.1)[https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift/releases/tag/v0.10.1]
- Updated eudi-lib-ios-statium-swift library to (v0.2.0)[https://github.com/eu-digital-identity-wallet/eudi-lib-ios-statium-swift/releases/tag/v0.2.0]
- Add Sendable conformance to TransactionLogData and PresentationLogData structs.

## v0.10.8
- Modified BLE data transfer initialisation to ensure BLE powered on before advertising UUID service and presenting QR code

## v0.10.7
### Document Status Checks
- Integration with `eudi-lib-ios-statium-swift` library for document status checks (Token Status List Specification [draft 10](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html))
- Added `public func getDocumentStatus(for statusIdentifier: StatusIdentifier) async throws -> CredentialStatus` method to `EudiWallet` class.
```swift
for m in wallet.storage.docModels {
	guard let st = m.statusIdentifier else { continue }
	let status = try? await wallet.getDocumentStatus(for: st)
	// mark document according to its status as active or revoked, etc...
}


## v0.10.6
### OpenID4VCI - Draft 15
- Updated OpenID4VCI library to version [0.13.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.13.0)
- Issuing functions updated to work with OpenID4VCI - Draft 15

### Transaction logging
- To log the transaction data, provide an implementation of the `TransactionLogger` protocol:
```swift
public actor DbTransactionLogger: TransactionLogger {
	public func log(transaction: TransactionLog) async throws {
		// Implement your logging logic here
	}
}
```

- Set the `transactionLogger` property of the `EudiWallet` instance to a `TransactionLogger` implementation instance:
```swift
wallet.transactionLogger = DbTransactionLogger()
```
- To display presented documents for a transaction, use the `parseTransactionLog` function of the `EudiWallet` instance:
```swift
let presentationData = await wallet.parseTransactionLog(transaction)
```

## v0.10.5
- Updated OpenID4VP library to version [v0.9.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp/releases/tag/v0.9.0)
- Updated OpenID4VCI library to version [0.12.3](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.12.3)

## v0.10.4
- Support transaction data for OpenID4VP
- Fix issue #162
- Fix issue #163

## v0.10.3
- Removed `vct` from `docClaims` collection.

## v0.10.2
- Simplified OpenID4VCI configuration
```swift
wallet = try! EudiWallet(serviceName: Self.serviceName, trustedReaderCertificates: certs,
  openID4VciConfig: OpenId4VCIConfiguration(useDPoP: true), logFileName: "temp.txt", secureAreas: [mySecureArea])
```

## v0.10.1
- OpenID4VP Draft 23 support

## v0.10.0
- Fix nil DocClaim issue for request-items

## v0.9.9
- `DocPresentInfo` struct members public
- `DocClaim`: added property `path: [String]` to store the path of the claim in the document

## v0.9.8
 - sdJwt nested elements presentation
 - `DocElementsViewModel` replaced with `enum DocElements`

## v0.9.6
- OfferedIssuanceModel: Change the issuerName property to represent a friendly name instead of a URL and add a new issuerLogoUrl property

## v0.9.5
- Updated `eudi-lib-ios-openid4vci-swift` library to version [v0.12.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.12.0)
- `openID4VciConfig` now accepts a `DPoPConstructorType`.
- Updated `eudi-lib-ios-siop-openid4vp-swift` library to version [v0.7.0](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift/releases/tag/v0.7.0)
### Breaking changes
- `ElementViewModel`: removed `elementIdentifier` and `displayName` properties and added `elementPath` and `displayNames` properties:
```
/// path to locate the element
public let elementPath: [String]
// display names of the component paths
public let displayNames: [String?]
```

## v0.9.4
- Added properties to `DocClaimsDecodable` protocol: `validFrom`, `validUntil`
## v0.9.3
- Fixed bug for OpenID4VP presentation for more than 2 documents
## v0.9.2
- Fixed bugs for OpenID4VP presentation
- Added properties to `DocClaimsDecodable` protocol: `issuerDisplay`,`credentialIssuerIdentifier`, `configurationIdentifier`
## v0.9.1
- `EudiWallet`: added `uiCulture` string property for UI localization. It must be a 2-letter language code (optional)
- `EudiWallet`: added `getIssuerMetadata()` function to retrieve selected issuer's metadata
- `EudiWallet`: Issue document using either doc-type, scope or configuration identifier:  `func issueDocument(docType: String?, scope: String?, identifier: String?, promptMessage: String? = nil)`
- `WalletStorage.Document`: added `displayName` property with localized string value
- `ElementViewModel`: added `displayName` property with localized string value
- `DocMetadata`: stores all localized metadata in `display` property
- `DocClaimMetadata`: stores all localized metadata in `display` property
- Fix bug with VP presentation
## v0.9.0
### Supports issuing and display of documents with sd-jwt-vc format
- `DocClaimDecodable` protocol is supported for both mso-mdoc (cbor) and sd-jwt-vc formats
### Supports saving and retrieving issuer metadata to be used for display
- `DocClaim` struct has `docDataValue` property to store the typed value (enum with associated values) of the claim and `stringValue` property to store the string value of the claim
- `DocClaim` struct has `displayName`, `isOptional` and `valueType` properties provided by the issuer
### Updated eudi-lib-ios-openid4vci-swift to version 0.10.0
- Feature/dpop nonce
### Breaking changes
- `StorageManager` property `mdocModels` renamed to `docModels`
- `MdocDecodable` protocol renamed to `DocClaimDecodable`
- `NameValue` struct renamed to `DocClaim`
- `NameImage` struct removed

## v0.8.2
- Update for OpenID4VCI Draft14 (eudi-lib-ios-openid4vci-swift updated to tag 0.9.0)
- Use @MainActor for issuing methods due to authentication UI

## v0.8.1
### Breaking changes
- `SecureArea` protocol static factory method added: `nonisolated public static func create(storage: any SecureKeyStorage) -> Self`
- Removed `SecureArea` protocol initializer: `init(storage: any SecureKeyStorage)` (use the static factory method instead)
- Removed property `storage` from `SecureArea` protocol

## v0.8.0
### Secure area refactoring
####  `EudiWallet` changes:
- `init` added `secureAreas`: `[SecureArea]` optional parameter (default is `["SecureEnclave", "Software"]`)
- `issueDocument`: added `keyOptions` optional parameter to specify the secure area name and other key options for the key creation
- `issueDocumentsByOfferUrl`: added `docTypeKeyOptions` optional parameter to specify the secure area name and other key options for each doc type

## v0.7.8
- `RequestItems` conforms to `Equatable` protocol

## v0.7.7
 - Fix issue [#118](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/118)
 ### Breaking changes
- `RequestItems` is now a dictionary with a key of type `String` (doc-type) and a value of type `[String: [RequestItem]]` (namespace to request items)
- `RequestItem` is a struct with the following properties: `elementIdentifier`, `intentToRetain` and `isOptional`
 ```swift
 public typealias RequestItems = [String: [String: [RequestItem]]]
```
- ElementViewModel: `public var isMandatory: Bool` is removed
- ElementViewModel: `public var isOptional: Bool` is added (opposite of `isMandatory`)

## v0.7.4
- Update Package.resolved and Package.swift with new versions for openid4vci, openid4vp

## v0.7.3
- Bug fix

## v0.7.2
- Removed `@MainActor` annotation from class definitions

## v0.7.1
- Swift 6 migration

## v0.7.0
- Updated OpenID4VCI to version 0.6.0

## v0.6.9
- Fill document display name in [DocElementsViewModel](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-wallet-kit/documentation/eudiwalletkit/docelementsviewmodel/)

## v0.6.8
- Updated OpenID4VCI to version 0.5.0
- Updated OpenID4VP to version 0.4.0

## v0.6.7

### Added methods:
- `public func loadDocument(id:status:) async throws -> WalletStorage.Document?`
- `public func deleteDocument(id:status:) async throws`

### Documentation
- Updated README.md with new methods and explanations
- Added documentation using Swift-DocC (deployed [here](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-wallet-kit/documentation/eudiwalletkit/))

## v0.6.5
### Fixes for dynamic issuance:
 - Support dynamic issuance in scoped mode
 - Remove pending document after finalizing `resumePendingIssuance`

## v0.6.4
- New wallet methods:

` public func loadAllDocuments() async throws -> [WalletStorage.Document]? `

` public func deleteAllDocuments() async throws `

` public func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?) async throws -> WalletStorage.Document `

- Dynamic issuance handling:
After calling issueDocumentsByOfferUrl the wallet application need to check if the issuance is pending:

`if let urlString = newDocs.first?.authorizePresentationUrl { `

`	// perform openid4vp presentation using the urlString `

`	// on success call resumePendingIssuance using the url provided by the server `

## v0.6.3
- Fixed issuing error when wallet `userAuthenticationRequired` property is true

## v0.6.2
### Fix
- [Wrong text on success message after issuing a document](https://github.com/eu-digital-identity-wallet/eudi-doc-testing-application-internal/issues/7): `OfferedIssuanceModel`, `issuerName` now has only the domain
### Logging mechanism
- `EudiWallet` supports logging and retrieval of log contents

	` // If not-nil, logging to the specified log file name will be configured
	 public var logFileName: String? { didSet { try? initializeLogging() } }

	// Helper method to return a file URL from a file name.
	public static func getLogFileURL(_ fileName: String) throws -> URL?

	// Reset a log file stored in the caches directory
e.g. 	wallet.serviceName = "wallet_dev"

## v0.5.8
- Update eudi-lib-ios-openid4vci-swift to version [0.4.2](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.4.2)
	public func resetLogFile(_ fileName: String) throws openID4VciConfig: OpenId4VCIConfig?` to pass OpenID4VCI issuer parameters
- Removed `EudiWallet` properties `var openID4VciClientId` and `var openID4VciRedirectUri`
	// Get the contents of a log file stored in the caches directory
	public func getLogFileContents(_ fileName: String) throws -> String
  `

## v0.6.1- `loadDocuments` takes an optional `status` parameter of type `WalletStorage.DocumentStatus` (default is `issued`)
- Set WalletStorage.Document displayName property when saving a document- `deleteDocuments` takes an optional `status` parameter of type `WalletStorage.DocumentStatus` (default is `issued`)
iable `@Published public private(set) var deferredDocuments: [WalletStorage.Document] = []` (documents that are not yet issued)
## v0.6.0
- Update eudi-lib-ios-openid4vci-swift to version 0.4.3h the issued document.
pdated.
## v0.5.9) async throws -> WalletStorage.Document`
- `EudiWallet` new property `public var serviceName: String`

Use a different `serviceName` than the default one if you want to store documents in a different location.4vci-swift/releases/tag/v0.4.1)
e.g. 	wallet.serviceName = "wallet_dev"
dded property `public var accessGroup: String?` (used for sharing keychain items between apps with the same access group)
## v0.5.8
- Update eudi-lib-ios-openid4vci-swift to version [0.4.2](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.4.2)
- New `EudiWallet` property `public var openID4VciConfig: OpenId4VCIConfig?` to pass OpenID4VCI issuer parameters0.3.2
- Removed `EudiWallet` properties `var openID4VciClientId` and `var openID4VciRedirectUri`
## v0.5.5
eudi-lib-ios-openid4vci-swift to version 0.3.1
## v0.5.7
### StorageManager changes## v0.5.4
- `loadDocuments` takes an optional `status` parameter of type `WalletStorage.DocumentStatus` (default is `issued`)m URLSession variable
- `deleteDocuments` takes an optional `status` parameter of type `WalletStorage.DocumentStatus` (default is `issued`) `EudiWallet` class. This variable can be used to set a custom URLSession for network requests. Allows for custom configuration of the URLSession, such as setting a custom timeout interval or Self-Signed certificates.
- new variable `@Published public private(set) var deferredDocuments: [WalletStorage.Document] = []` (documents that are not yet issued)
### Deferred issuance
-	Request a deferred issuance based on a stored deferred document. On success, the deferred document is updated with the issued document.
   The caller does not need to reload documents, storage manager `deferredDocuments` and `docModels` properties are updated.
- New function to request deferred issuance: `@discardableResult public func requestDeferredIssuance(deferredDoc: WalletStorage.Document) async throws -> WalletStorage.Document`## v0.5.2
### Other changesrt Pre-Authorized Code Flow
- Removed `otherModels`, `docTypes`, `documentIds` properties
- Updated eudi-lib-ios-openid4vci-swift to version [0.4.1](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.4.1)The flow is supported by existing methods:
- Rename `OfferedIssueModel` to `OfferedIssuanceModel`
- `EudiWallet`: added property `public var accessGroup: String?` (used for sharing keychain items between apps with the same access group)he following method is called: `public func resolveOfferUrlDocTypes(uriOffer: String) async throws -> OfferedIssueModel`
### (Breaking change, the return value type is `OfferedIssueModel` instead of `[OfferedDocModel]`)
## v0.5.6
- Update eudi-lib-ios-siop-openid4vp to version 0.3.22 - If `OfferedIssueModel.isTxCodeRequired` is true, the call to `` must include the transaction code (parameter `txCodeValue`).

## v0.5.5
- Update eudi-lib-ios-openid4vci-swift to version 0.3.1

## v0.5.4### Update eudi-lib-ios-openid4vci-swift dependency to version 0.1.5
### Custom URLSession variable
- Added `public var urlSession: URLSession` variable to `EudiWallet` class. This variable can be used to set a custom URLSession for network requests. Allows for custom configuration of the URLSession, such as setting a custom timeout interval or Self-Signed certificates.- Update eudi-lib-ios-openid4vci-swift dependency to version 0.1.5
OS16 offer url parsing issue
## v0.5.3
- Library updates## v0.5.0

## v0.5.2
### Support Pre-Authorized Code Flow## v0.4.9
d4VP fixes and updates
The flow is supported by existing methods:
- Update eudi-lib-ios-siop-openid4vp to version 0.1.1
1 - An issue offer url is scanned. The following method is called: `public func resolveOfferUrlDocTypes(uriOffer: String) async throws -> OfferedIssueModel`nid4vp certificate chain verification (PresentationSession's  `readerCertIssuerValid` and `readerCertIssuer` properties)
### (Breaking change, the return value type is `OfferedIssueModel` instead of `[OfferedDocModel]`)y to PresentationSession

2 - If `OfferedIssueModel.isTxCodeRequired` is true, the call to `` must include the transaction code (parameter `txCodeValue`).

- Note: for the clientId value the `EudiWallet/openID4VciClientId` is used.fierLegalName: String?` (used for Openid4VP preregistered clients)

## v0.5.1
### Update eudi-lib-ios-openid4vci-swift dependency to version 0.1.50

- Update eudi-lib-ios-openid4vci-swift dependency to version 0.1.5## v0.4.6
- Fixes iOS16 offer url parsing issuee openid4vci to version 0.1.2

## v0.5.0##v0.4.5
- `EuPidModel` updated with new PID docTypee eudi-lib-ios-openid4vci-swift to version 0.0.9

## v0.4.9## v0.4.4
### Openid4VP fixes and updatesking change - docModels contains not-nil items (SwiftUI breaks with nil items)

- Update eudi-lib-ios-siop-openid4vp to version 0.1.1
- Fix openid4vp certificate chain verification (PresentationSession's  `readerCertIssuerValid` and `readerCertIssuer` properties)
- Add `readerLegalName` property to PresentationSession

## v0.4.8- PresentationSession / func sendResponse: itemsToSend dictionary is keyed by docId (and not docType)
- Update eudi-lib-ios-siop-openid4vp to version 0.1.0
- Added wallet configuration parameter `public var verifierLegalName: String?` (used for Openid4VP preregistered clients)
 data
## v0.4.7
###Update eudi-lib-ios-siop-openid4vp to version 0.1.0

## v0.4.6
### Update openid4vci to version 0.1.2

##v0.4.5
### Update eudi-lib-ios-openid4vci-swift to version 0.0.9

## v0.4.4## v0.3.9
### Breaking change - docModels contains not-nil items (SwiftUI breaks with nil items)I: Allow partial issuing when some documents fail to issue
@Published public var docModels: [any MdocDecodable] = []
## v0.3.8
## v0.4.3I: Fixed issuing with https://dev.issuer.eudiw.dev
Openid4vp, BLE: Support sending multiple documents with same doc-type
- DocElementsViewModel: added `public var docId: String`## v0.3.7
- PresentationSession / func sendResponse: itemsToSend dictionary is keyed by docId (and not docType) functions:
ffer metadata are cached
## v0.4.2
Refactoring for issuing documents with IssuerSigned cbor datafunc resolveOfferUrlDocTypes(uriOffer: String) async throws -> [OfferedDocModel] `
### Breaking change: Document data is saved as encoded IssuerSigned cbor

## v0.4.1
OpenID4VCI: fix for filtering resolved identifierseKeyOptions: [String: KeyOptions]? = nil, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> [WalletStorage.Document] `
Support mdoc Authentication for OpenId4Vp #46

## v0.4.0 `// PresentationSession
OpenID4VCI fix
    use the following code to convert to QR code image:
## v0.3.9
OpenID4VCI: Allow partial issuing when some documents fail to issuengagement.getQrCodeImage(qrCode: d)`

## v0.3.8
OpenID4VCI: Fixed issuing with https://dev.issuer.eudiw.devUpdated `eudi-lib-ios-siop-openid4vp-swift` to v0.0.74

## v0.3.7
### Added functions:
/// Resolve OpenID4VCI offer URL document types. Resolved offer metadata are cached

` public func resolveOfferUrlDocTypes(uriOffer: String) async throws -> [OfferedDocModel] `

/// Issue documents by offer URI. createdAt),

`public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], docTypeKeyOptions: [String: KeyOptions]? = nil, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> [WalletStorage.Document] `## v0.3.3
VP draft 13 support
### Breaking change:
 `// PresentationSession## v0.3.2
 @Published public var deviceEngagement: String?`l updates for security checks
    use the following code to convert to QR code image:
## v0.3.1
 `let qrImage =  DeviceEngagement.getQrCodeImage(qrCode: d)` presentation definition parsing

## v0.3.6## v0.3.0
Updated `eudi-lib-ios-siop-openid4vp-swift` to v0.0.74 eudi-lib-ios-siop-openid4vp-swift to 0.0.72
Updated `eudi-lib-ios-openid4vci-swift` to v0.0.7
## v0.2.9
## v0.3.5DOC authentication MAC validation error for mDL document type
Updated `eudi-lib-ios-siop-openid4vp-swift` to v0.0.73
Updated `eudi-lib-ios-openid4vci-swift` to v0.0.6## v0.1.7
elete documents func
## v0.3.4
- Refactor MdocDecodable (DocType, DocumentIdentifier, createdAt),### MdocDataModel18013
DisplayStrings is recursive (cbor elements can be dictionaries)
## v0.3.3ren: [NameValue]` property (tree-like structure)
- OpenID4VP draft 13 supportage]' property

## v0.3.2
- Internal updates for security checks

## v0.3.1- `PresentationSession`: add `readerCertIssuerValid`` (is verifier certificate trusted)
- Updated presentation definition parsingtationSession`: change `readerCertIssuer`` (has verifier certificate common name)
() -> [String: Any]`
## v0.3.0
- Updated eudi-lib-ios-siop-openid4vp-swift to 0.0.72
et ([#86](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/86)) via [@phisakel](https://github.com/phisakel)
## v0.2.9ital-identity-wallet/eudi-lib-ios-wallet-kit/pull/74)) via [@phisakel](https://github.com/phisakel)
- Fixed mDOC authentication MAC validation error for mDL document type- Update documentation links in README.md ([#82](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/82)) via [@phisakel](https://github.com/phisakel)
ocumentation in README.md ([#81](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/81)) via [@phisakel](https://github.com/phisakel)
## v0.1.7
- Added delete documents func
- Storage manager functions are now `async throws`.com/phisakel)
### MdocDataModel18013com/phisakel)
- extractDisplayStrings is recursive (cbor elements can be dictionaries)
- NameValue: added `var children: [NameValue]` property (tree-like structure)akel](https://github.com/phisakel)
- MdocDecodable: added 'var displayImages: [NameImage]' property

## v0.1.6allet-kit/pull/68)) via [@phisakel](https://github.com/phisakel)
- Add isMandatory property to DocElementsViewModel structure via [@phisakel](https://github.com/phisakel)
- `PresentationSession` methods do not run on main actor) via [@phisakel](https://github.com/phisakel)
- `PresentationSession`: add `readerCertIssuerValid`` (is verifier certificate trusted)com/phisakel)
- `PresentationSession`: change `readerCertIssuer`` (has verifier certificate common name)
- `MdocDecodable`: add extension method: `public func toJson() -> [String: Any]`

## Pull requests
- Update eudi-lib-ios-openid4vci-swift to version 0.4.2 and add new properties to EudiWallet ([#86](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/86)) via [@phisakel](https://github.com/phisakel)
- Refactor to support Deferred document issuing ([#74](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/74)) via [@phisakel](https://github.com/phisakel)56)) via [@phisakel](https://github.com/phisakel)
- Update documentation links in README.md ([#82](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/82)) via [@phisakel](https://github.com/phisakel)b.com/phisakel)
- Docs: update documentation in README.md ([#81](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/81)) via [@phisakel](https://github.com/phisakel)
- VP version 0.3.2, docs with Swift-DocC Plugin ([#80](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/80)) via [@phisakel](https://github.com/phisakel)github.com/phisakel)
- Update PGP Key link ([#79](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/79)) via [@mgiakkou](https://github.com/mgiakkou)
- Update eudi-lib-ios-openid4vci-swift to version 0.3.1 ([#78](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/78)) via [@phisakel](https://github.com/phisakel)om/phisakel)
- Allow Self-Signed SSL for OpenId4VCI and OpenId4VP ([#76](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/76)) via [@phisakel](https://github.com/phisakel)/github.com/phisakel)
- [fix] pre-auth fixes in libs ([#75](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/75)) via [@dtsiflit](https://github.com/dtsiflit)l/44)) via [@phisakel](https://github.com/phisakel)
- Support Pre-Authorized Code Flow - Wallet-kit (iOS) ([#72](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/72)) via [@phisakel](https://github.com/phisakel)ttps://github.com/phisakel)
- Fix swift.yml ([#71](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/71)) via [@phisakel](https://github.com/phisakel)bashov)
- Credential offer URL parsing issue for iOS16 ([#69](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/69)) via [@phisakel](https://github.com/phisakel)servosNCIN)
- Update eudi-lib-ios-iso18013-data-model and eudi-lib-ios-iso18013-data-transfer dependencies ([#68](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/68)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.1.1, fix verifier display name, valid status ([#67](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/67)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.1.0 ([#64](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/64)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.1.0 ([#64](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/64)) via [@phisakel](https://github.com/phisakel)
- Update openid4vci library to version 0.1.2 ([#62](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/62)) via [@phisakel](https://github.com/phisakel)i-lib-ios-wallet-kit/pull/34)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-openid4vci-swift to version 0.0.9 ([#61](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/61)) via [@phisakel](https://github.com/phisakel)
- Issuing - Support for credential offer ([#45](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/45)) via [@phisakel](https://github.com/phisakel)kel)
- OpenID4VCI draft13 support ([#31](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/31)) via [@phisakel](https://github.com/phisakel))
- Simplify Storage Manager API ([#59](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/59)) via [@phisakel](https://github.com/phisakel)
- Openid4vp and BLE should support sending response with multiple documents of the same doc-type (iOS) ([#56](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/56)) via [@phisakel](https://github.com/phisakel)@phisakel](https://github.com/phisakel)
- Refactor to support IssuerSigned CBOR structure [iOS] ([#53](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/53)) via [@phisakel](https://github.com/phisakel)
- Changelog.md update ([#51](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/51)) via [@phisakel](https://github.com/phisakel)
- Vci offer fix for filtering resolved identifiers ([#50](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/50)) via [@phisakel](https://github.com/phisakel)
- Support mdoc Authentication for OpenId4Vp ([#46](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/46)) via [@phisakel](https://github.com/phisakel)
- OpenID4VCI: Allow partial issuing when some documents fail to issue ([#48](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/48)) via [@phisakel](https://github.com/phisakel)
- Issuing - Support for credential offer ([#45](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/45)) via [@phisakel](https://github.com/phisakel).com/phisakel)
- Support OpenID4VCI credential offer (resolution of credential offer, issuing of specific doc types) ([#44](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/44)) via [@phisakel](https://github.com/phisakel)ithub.com/phisakel)
- Chore: Update dependencies for udi-lib-ios-iso18013-data-transfer to … ([#43](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/43)) via [@phisakel](https://github.com/phisakel)
- Return the QR code to the device engagement in string representation ([#42](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/42)) via [@akarabashov](https://github.com/akarabashov)](https://github.com/phisakel)
- Centralization of sec workflows ([#21](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/21)) via [@christosservosNCIN](https://github.com/christosservosNCIN)
- [fix] sdjwt case fix ([#36](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/36)) via [@dtsiflit](https://github.com/dtsiflit)
- Update openid4vci library to v0.0.7 ([#39](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/39)) via [@phisakel](https://github.com/phisakel)
- Update OpenID4VP to v0.0.74 ([#37](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/37)) via [@phisakel](https://github.com/phisakel)
- Update dependencies to latest versions ([#35](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/35)) via [@phisakel](https://github.com/phisakel)sakel](https://github.com/phisakel)
- Update dependencies and refactor StorageManager to support multiple documents with same docType ([#34](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/34)) via [@phisakel](https://github.com/phisakel)
- Update changelog.md ([#32](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/32)) via [@phisakel](https://github.com/phisakel)
- Update dependencies and changelog ([#30](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/30)) via [@phisakel](https://github.com/phisakel)/phisakel)
- Updates due to security helpers changes ([#29](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/29)) via [@phisakel](https://github.com/phisakel)ithub.com/phisakel)
- Updated Presentation Definition Parsing ([#28](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/28)) via [@phisakel](https://github.com/phisakel)ithub.com/phisakel)
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.0.72 ([#27](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/27)) via [@phisakel](https://github.com/phisakel)
- Check if iaca variable is nil, refactor to use multiple device private keys ([#23](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/23)) via [@phisakel](https://github.com/phisakel)
- Update README.md ([#25](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/25)) via [@vkanellopoulos](https://github.com/vkanellopoulos)- Update SECURITY.md ([#22](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/22)) via [@vkanellopoulos](https://github.com/vkanellopoulos)- Use subjectDistinguishedName for openID4vp verifier, update packages ([#20](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/20)) via [@phisakel](https://github.com/phisakel)- Fix for verifier name ([#19](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/19)) via [@phisakel](https://github.com/phisakel)- Reader auth for openid4vp, readme overview ([#18](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/18)) via [@phisakel](https://github.com/phisakel)
- SendResponse takes an onSuccess callback function ([#17](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/17)) via [@phisakel](https://github.com/phisakel)
- Add BlueECC dependency and update eudi-lib-ios-siop-openid4vp version ([#16](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/16)) via [@phisakel](https://github.com/phisakel)
- OpenID4VciRedirectUri public property in wallet kit ([#15](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/15)) via [@phisakel](https://github.com/phisakel)
- Changes for Secure Enclave use ([#14](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/14)) via [@phisakel](https://github.com/phisakel)
- Fixes after updating OpenID4VCI library ([#13](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/13)) via [@phisakel](https://github.com/phisakel)
- Issue documents using OpenID4VCI protocol ([#12](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/12)) via [@phisakel](https://github.com/phisakel)
- Bug fixes for storage manager ([#11](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/11)) via [@phisakel](https://github.com/phisakel)
- Method to begin presentation using any custom PresentationService ([#10](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/10)) via [@phisakel](https://github.com/phisakel)
- Update README and SECURITY.md files ([#9](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/9)) via [@phisakel](https://github.com/phisakel)
- Added delete documents func to wallet kit ([#8](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/8)) via [@phisakel](https://github.com/phisakel)
- Make storage manager methods async throws ([#7](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/7)) via [@phisakel](https://github.com/phisakel)
- Update Package.resolved and add isMandatory property to DocElementsViewModel structure ([#6](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/6)) via [@phisakel](https://github.com/phisakel)
- Develop: limit main actor usage, reader cert variables ([#5](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/5)) via [@phisakel](https://github.com/phisakel)
- Update License and Copyright ([#4](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/4)) via [@phisakel](https://github.com/phisakel)
- Develop ([#3](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/3)) via [@phisakel](https://github.com/phisakel)
