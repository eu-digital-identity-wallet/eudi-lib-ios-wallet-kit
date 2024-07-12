## v0.5.7
- Update eudi-lib-ios-openid4vci-swift to version 0.3.2
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

1 - An issue offer url is scanned. The following method is called: `public func resolveOfferUrlDocTypes(uriOffer: String, format: DataFormat = .cbor, useSecureEnclave: Bool = true) async throws -> OfferedIssueModel`
### (Breaking change, the return value type is `OfferedIssueModel` instead of `[OfferedDocModel]`)

2 - If `OfferedIssueModel.isTxCodeRequired` is true, the call to `issueDocumentsByOfferUrl` must include the transaction code (parameter `txCodeValue`). 

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
### Breaking change - mdocModels contains not-nil items (SwiftUI breaks with nil items)
@Published public var mdocModels: [any MdocDecodable] = []

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

` public func resolveOfferUrlDocTypes(uriOffer: String, format: DataFormat = .cbor, useSecureEnclave: Bool = true) async throws -> [OfferedDocModel] `

/// Issue documents by offer URI.

`public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], format: DataFormat, promptMessage: String? = nil, useSecureEnclave: Bool = true, claimSet: ClaimSet? = nil) async throws -> [WalletStorage.Document] `

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
