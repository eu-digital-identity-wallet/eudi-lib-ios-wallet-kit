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
	public func resetLogFile(_ fileName: String) throws  

	// Get the contents of a log file stored in the caches directory
	public func getLogFileContents(_ fileName: String) throws -> String	
  `	

## v0.6.1
- Set WalletStorage.Document displayName property when saving a document

## v0.6.0
- Update eudi-lib-ios-openid4vci-swift to version 0.4.3

## v0.5.9
- `EudiWallet` new property `public var serviceName: String`

Use a different `serviceName` than the default one if you want to store documents in a different location.
e.g. 	wallet.serviceName = "wallet_dev"

## v0.5.8
- Update eudi-lib-ios-openid4vci-swift to version [0.4.2](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.4.2)
- New `EudiWallet` property `public var openID4VciConfig: OpenId4VCIConfig?` to pass OpenID4VCI issuer parameters
- Removed `EudiWallet` properties `var openID4VciClientId` and `var openID4VciRedirectUri`


## v0.5.7
### StorageManager changes
- `loadDocuments` takes an optional `status` parameter of type `WalletStorage.DocumentStatus` (default is `issued`)
- `deleteDocuments` takes an optional `status` parameter of type `WalletStorage.DocumentStatus` (default is `issued`)
- new variable `@Published public private(set) var deferredDocuments: [WalletStorage.Document] = []` (documents that are not yet issued)
### Deferred issuance
-	Request a deferred issuance based on a stored deferred document. On success, the deferred document is updated with the issued document.
   The caller does not need to reload documents, storage manager `deferredDocuments` and `docModels` properties are updated.
- New function to request deferred issuance: `@discardableResult public func requestDeferredIssuance(deferredDoc: WalletStorage.Document) async throws -> WalletStorage.Document`
### Other changes
- Removed `otherModels`, `docTypes`, `documentIds` properties
- Updated eudi-lib-ios-openid4vci-swift to version [0.4.1](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift/releases/tag/v0.4.1)
- Rename `OfferedIssueModel` to `OfferedIssuanceModel` 
- `EudiWallet`: added property `public var accessGroup: String?` (used for sharing keychain items between apps with the same access group)

## v0.5.6
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.3.2

## v0.5.5
- Update eudi-lib-ios-openid4vci-swift to version 0.3.1

## v0.5.4
### Custom URLSession variable
- Added `public var urlSession: URLSession` variable to `EudiWallet` class. This variable can be used to set a custom URLSession for network requests. Allows for custom configuration of the URLSession, such as setting a custom timeout interval or Self-Signed certificates.

## v0.5.3
- Library updates

## v0.5.2
### Support Pre-Authorized Code Flow

The flow is supported by existing methods:

1 - An issue offer url is scanned. The following method is called: `public func resolveOfferUrlDocTypes(uriOffer: String) async throws -> OfferedIssueModel`
### (Breaking change, the return value type is `OfferedIssueModel` instead of `[OfferedDocModel]`)

2 - If `OfferedIssueModel.isTxCodeRequired` is true, the call to `` must include the transaction code (parameter `txCodeValue`). 

- Note: for the clientId value the `EudiWallet/openID4VciClientId` is used.

## v0.5.1
### Update eudi-lib-ios-openid4vci-swift dependency to version 0.1.5

- Update eudi-lib-ios-openid4vci-swift dependency to version 0.1.5
- Fixes iOS16 offer url parsing issue

## v0.5.0
- `EuPidModel` updated with new PID docType

## v0.4.9
### Openid4VP fixes and updates

- Update eudi-lib-ios-siop-openid4vp-swift to version 0.1.1
- Fix openid4vp certificate chain verification (PresentationSession's  `readerCertIssuerValid` and `readerCertIssuer` properties)
- Add `readerLegalName` property to PresentationSession

## v0.4.8
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.1.0
- Added wallet configuration parameter `public var verifierLegalName: String?` (used for Openid4VP preregistered clients)

## v0.4.7
###Update eudi-lib-ios-siop-openid4vp-swift to version 0.1.0

## v0.4.6
### Update openid4vci to version 0.1.2

##v0.4.5
### Update eudi-lib-ios-openid4vci-swift to version 0.0.9

## v0.4.4
### Breaking change - docModels contains not-nil items (SwiftUI breaks with nil items)
@Published public var docModels: [any MdocDecodable] = []

## v0.4.3
Openid4vp, BLE: Support sending multiple documents with same doc-type
- DocElementsViewModel: added `public var docId: String`
- PresentationSession / func sendResponse: itemsToSend dictionary is keyed by docId (and not docType) 

## v0.4.2
Refactoring for issuing documents with IssuerSigned cbor data
### Breaking change: Document data is saved as encoded IssuerSigned cbor

## v0.4.1
OpenID4VCI: fix for filtering resolved identifiers
Support mdoc Authentication for OpenId4Vp #46

## v0.4.0
OpenID4VCI fix

## v0.3.9
OpenID4VCI: Allow partial issuing when some documents fail to issue

## v0.3.8
OpenID4VCI: Fixed issuing with https://dev.issuer.eudiw.dev

## v0.3.7
### Added functions:
/// Resolve OpenID4VCI offer URL document types. Resolved offer metadata are cached

` public func resolveOfferUrlDocTypes(uriOffer: String) async throws -> [OfferedDocModel] `

/// Issue documents by offer URI.

`public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], docTypeKeyOptions: [String: KeyOptions]? = nil, promptMessage: String? = nil, claimSet: ClaimSet? = nil) async throws -> [WalletStorage.Document] `

### Breaking change: 
 `// PresentationSession
 @Published public var deviceEngagement: String?`
    use the following code to convert to QR code image:  
    
 `let qrImage =  DeviceEngagement.getQrCodeImage(qrCode: d)`

## v0.3.6
Updated `eudi-lib-ios-siop-openid4vp-swift` to v0.0.74
Updated `eudi-lib-ios-openid4vci-swift` to v0.0.7

## v0.3.5
Updated `eudi-lib-ios-siop-openid4vp-swift` to v0.0.73
Updated `eudi-lib-ios-openid4vci-swift` to v0.0.6

## v0.3.4
- Refactor MdocDecodable (DocType, DocumentIdentifier, createdAt), 

## v0.3.3
- OpenID4VP draft 13 support

## v0.3.2
- Internal updates for security checks

## v0.3.1
- Updated presentation definition parsing

## v0.3.0
- Updated eudi-lib-ios-siop-openid4vp-swift to 0.0.72

## v0.2.9
- Fixed mDOC authentication MAC validation error for mDL document type

## v0.1.7
- Added delete documents func
- Storage manager functions are now `async throws`
### MdocDataModel18013
- extractDisplayStrings is recursive (cbor elements can be dictionaries)
- NameValue: added `var children: [NameValue]` property (tree-like structure)
- MdocDecodable: added 'var displayImages: [NameImage]' property

## v0.1.6
- Add isMandatory property to DocElementsViewModel structure
- `PresentationSession` methods do not run on main actor
- `PresentationSession`: add `readerCertIssuerValid`` (is verifier certificate trusted)
- `PresentationSession`: change `readerCertIssuer`` (has verifier certificate common name)
- `MdocDecodable`: add extension method: `public func toJson() -> [String: Any]`

## Pull requests
- Update eudi-lib-ios-openid4vci-swift to version 0.4.2 and add new properties to EudiWallet ([#86](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/86)) via [@phisakel](https://github.com/phisakel)
- Refactor to support Deferred document issuing ([#74](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/74)) via [@phisakel](https://github.com/phisakel)
- Update documentation links in README.md ([#82](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/82)) via [@phisakel](https://github.com/phisakel)
- Docs: update documentation in README.md ([#81](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/81)) via [@phisakel](https://github.com/phisakel)
- VP version 0.3.2, docs with Swift-DocC Plugin ([#80](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/80)) via [@phisakel](https://github.com/phisakel)
- Update PGP Key link ([#79](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/79)) via [@mgiakkou](https://github.com/mgiakkou)
- Update eudi-lib-ios-openid4vci-swift to version 0.3.1 ([#78](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/78)) via [@phisakel](https://github.com/phisakel)
- Allow Self-Signed SSL for OpenId4VCI and OpenId4VP ([#76](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/76)) via [@phisakel](https://github.com/phisakel)
- [fix] pre-auth fixes in libs ([#75](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/75)) via [@dtsiflit](https://github.com/dtsiflit)
- Support Pre-Authorized Code Flow - Wallet-kit (iOS) ([#72](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/72)) via [@phisakel](https://github.com/phisakel)
- Fix swift.yml ([#71](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/71)) via [@phisakel](https://github.com/phisakel)
- Credential offer URL parsing issue for iOS16 ([#69](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/69)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-iso18013-data-model and eudi-lib-ios-iso18013-data-transfer dependencies ([#68](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/68)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.1.1, fix verifier display name, valid status ([#67](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/67)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.1.0 ([#64](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/64)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.1.0 ([#64](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/64)) via [@phisakel](https://github.com/phisakel)
- Update openid4vci library to version 0.1.2 ([#62](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/62)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-openid4vci-swift to version 0.0.9 ([#61](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/61)) via [@phisakel](https://github.com/phisakel)
- Issuing - Support for credential offer ([#45](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/45)) via [@phisakel](https://github.com/phisakel)
- OpenID4VCI draft13 support ([#31](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/31)) via [@phisakel](https://github.com/phisakel)
- Simplify Storage Manager API ([#59](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/59)) via [@phisakel](https://github.com/phisakel)
- Openid4vp and BLE should support sending response with multiple documents of the same doc-type (iOS) ([#56](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/56)) via [@phisakel](https://github.com/phisakel)
- Refactor to support IssuerSigned CBOR structure [iOS] ([#53](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/53)) via [@phisakel](https://github.com/phisakel)
- Changelog.md update ([#51](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/51)) via [@phisakel](https://github.com/phisakel)
- Vci offer fix for filtering resolved identifiers ([#50](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/50)) via [@phisakel](https://github.com/phisakel)
- Support mdoc Authentication for OpenId4Vp ([#46](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/46)) via [@phisakel](https://github.com/phisakel)
- OpenID4VCI: Allow partial issuing when some documents fail to issue ([#48](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/48)) via [@phisakel](https://github.com/phisakel)
- Issuing - Support for credential offer ([#45](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/45)) via [@phisakel](https://github.com/phisakel)
- Support OpenID4VCI credential offer (resolution of credential offer, issuing of specific doc types) ([#44](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/44)) via [@phisakel](https://github.com/phisakel)
- Chore: Update dependencies for udi-lib-ios-iso18013-data-transfer to … ([#43](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/43)) via [@phisakel](https://github.com/phisakel)
- Return the QR code to the device engagement in string representation ([#42](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/42)) via [@akarabashov](https://github.com/akarabashov)
- Centralization of sec workflows ([#21](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/21)) via [@christosservosNCIN](https://github.com/christosservosNCIN)
- [fix] sdjwt case fix ([#36](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/36)) via [@dtsiflit](https://github.com/dtsiflit)
- Update openid4vci library to v0.0.7 ([#39](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/39)) via [@phisakel](https://github.com/phisakel)
- Update OpenID4VP to v0.0.74 ([#37](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/issues/37)) via [@phisakel](https://github.com/phisakel)
- Update dependencies to latest versions ([#35](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/35)) via [@phisakel](https://github.com/phisakel)
- Update dependencies and refactor StorageManager to support multiple documents with same docType ([#34](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/34)) via [@phisakel](https://github.com/phisakel)
- Update changelog.md ([#32](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/32)) via [@phisakel](https://github.com/phisakel)
- Update dependencies and changelog ([#30](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/30)) via [@phisakel](https://github.com/phisakel)
- Updates due to security helpers changes ([#29](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/29)) via [@phisakel](https://github.com/phisakel)
- Updated Presentation Definition Parsing ([#28](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/28)) via [@phisakel](https://github.com/phisakel)
- Update eudi-lib-ios-siop-openid4vp-swift to version 0.0.72 ([#27](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/27)) via [@phisakel](https://github.com/phisakel)
- Check if iaca variable is nil, refactor to use multiple device private keys ([#23](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/23)) via [@phisakel](https://github.com/phisakel)
- Update README.md ([#25](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/25)) via [@vkanellopoulos](https://github.com/vkanellopoulos)
- Update SECURITY.md ([#22](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/22)) via [@vkanellopoulos](https://github.com/vkanellopoulos)
- Use subjectDistinguishedName for openID4vp verifier, update packages ([#20](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/20)) via [@phisakel](https://github.com/phisakel)
- Fix for verifier name ([#19](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/19)) via [@phisakel](https://github.com/phisakel)
- Reader auth for openid4vp, readme overview ([#18](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/18)) via [@phisakel](https://github.com/phisakel)
- SendResponse takes an onSuccess callback function ([#17](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/17)) via [@phisakel](https://github.com/phisakel)
- Add BlueECC dependency and update eudi-lib-ios-siop-openid4vp-swift version ([#16](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit/pull/16)) via [@phisakel](https://github.com/phisakel)
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
