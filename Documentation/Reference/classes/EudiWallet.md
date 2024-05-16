**CLASS**

# `EudiWallet`

**Contents**

- [Properties](#properties)
  - `storage`
  - `standard`
  - `userAuthenticationRequired`
  - `trustedReaderCertificates`
  - `deviceAuthMethod`
  - `verifierApiUri`
  - `openID4VciIssuerUrl`
  - `openID4VciClientId`
  - `openID4VciRedirectUri`
  - `useSecureEnclave`
- [Methods](#methods)
  - `init(storageType:serviceName:accessGroup:trustedReaderCertificates:userAuthenticationRequired:verifierApiUri:openID4VciIssuerUrl:openID4VciClientId:openID4VciRedirectUri:)`
  - `issueDocument(docType:format:)`
  - `beginIssueDocument(id:privateKeyType:)`
  - `endIssueDocument(_:)`
  - `loadDocuments()`
  - `deleteDocuments()`
  - `loadSampleData(sampleDataFiles:)`
  - `prepareServiceDataParameters(docType:dataFormat:)`
  - `beginPresentation(flow:docType:dataFormat:)`
  - `beginPresentation(service:)`
  - `authorizedAction(action:disabled:dismiss:localizedReason:)`

```swift
public final class EudiWallet: ObservableObject
```

User wallet implementation

## Properties
### `storage`

```swift
public private(set) var storage: StorageManager
```

Storage manager instance

### `standard`

```swift
public static private(set) var standard: EudiWallet = EudiWallet()
```

Instance of the wallet initialized with default parameters

### `userAuthenticationRequired`

```swift
public var userAuthenticationRequired: Bool
```

Whether user authentication via biometrics or passcode is required before sending user data

### `trustedReaderCertificates`

```swift
public var trustedReaderCertificates: [Data]?
```

Trusted root certificates to validate the reader authentication certificate included in the proximity request

### `deviceAuthMethod`

```swift
public var deviceAuthMethod: DeviceAuthMethod = .deviceMac
```

Method to perform mdoc authentication (MAC or signature). Defaults to device MAC

### `verifierApiUri`

```swift
public var verifierApiUri: String?
```

OpenID4VP verifier api URL (used for preregistered clients)

### `openID4VciIssuerUrl`

```swift
public var openID4VciIssuerUrl: String?
```

OpenID4VCI issuer url

### `openID4VciClientId`

```swift
public var openID4VciClientId: String?
```

OpenID4VCI client id

### `openID4VciRedirectUri`

```swift
public var openID4VciRedirectUri: String = "eudi-openid4ci://authorize/"
```

OpenID4VCI redirect URI. Defaults to "eudi-openid4ci://authorize/"

### `useSecureEnclave`

```swift
public var useSecureEnclave: Bool
```

Use iPhone Secure Enclave to protect keys and perform cryptographic operations. Defaults to true (if available)

## Methods
### `init(storageType:serviceName:accessGroup:trustedReaderCertificates:userAuthenticationRequired:verifierApiUri:openID4VciIssuerUrl:openID4VciClientId:openID4VciRedirectUri:)`

```swift
public init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true, verifierApiUri: String? = nil, openID4VciIssuerUrl: String? = nil, openID4VciClientId: String? = nil, openID4VciRedirectUri: String? = nil)
```

Initialize a wallet instance. All parameters are optional.

### `issueDocument(docType:format:)`

```swift
@discardableResult public func issueDocument(docType: String, format: DataFormat = .cbor) async throws -> WalletStorage.Document
```

Issue a document with the given docType using OpenId4Vci protocol

If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
 - Parameters:
  - docType: Document type
  - format: Optional format type. Defaults to cbor
- Returns: The document issued. It is saved in storage.

### `beginIssueDocument(id:privateKeyType:saveToStorage:)`

```swift
public func beginIssueDocument(id: String, privateKeyType: PrivateKeyType = .secureEnclaveP256, saveToStorage: Bool = true) async throws -> IssueRequest
```

Begin issuing a document by generating an issue request

- Parameters:
  - id: Document identifier
  - issuer: Issuer function

#### Parameters

| Name | Description |
| ---- | ----------- |
| id | Document identifier |
| issuer | Issuer function |

### `endIssueDocument(_:)`

```swift
public func endIssueDocument(_ issued: WalletStorage.Document) throws
```

End issuing by saving the issuing document (and its private key) in storage
- Parameter issued: The issued document

#### Parameters

| Name | Description |
| ---- | ----------- |
| issued | The issued document |

### `loadDocuments()`

```swift
@discardableResult public func loadDocuments() async throws -> [WalletStorage.Document]?
```

Load documents from storage

Calls ``storage`` loadDocuments
- Returns: An array of ``WalletStorage.Document`` objects

### `deleteDocuments()`

```swift
public func deleteDocuments() async throws
```

Delete all documents from storage

Calls ``storage`` loadDocuments
- Returns: An array of ``WalletStorage.Document`` objects

### `loadSampleData(sampleDataFiles:)`

```swift
public func loadSampleData(sampleDataFiles: [String]? = nil) async throws
```

Load sample data from json files

The mdoc data are stored in wallet storage as documents
- Parameter sampleDataFiles: Names of sample files provided in the app bundle

#### Parameters

| Name | Description |
| ---- | ----------- |
| sampleDataFiles | Names of sample files provided in the app bundle |

### `prepareServiceDataParameters(docType:dataFormat:)`

```swift
public func prepareServiceDataParameters(docType: String? = nil, dataFormat: DataFormat = .cbor ) throws -> [String : Any]
```

Prepare Service Data Parameters
- Parameters:
  - docType: docType of documents to present (optional)
  - dataFormat: Exchanged data ``Format`` type
- Returns: A data dictionary that can be used to initialize a presentation service

#### Parameters

| Name | Description |
| ---- | ----------- |
| docType | docType of documents to present (optional) |
| dataFormat | Exchanged data `Format` type |

### `beginPresentation(flow:docType:dataFormat:)`

```swift
public func beginPresentation(flow: FlowType, docType: String? = nil, dataFormat: DataFormat = .cbor) -> PresentationSession
```

Begin attestation presentation to a verifier
- Parameters:
  - flow: Presentation ``FlowType`` instance
  - docType: DocType of documents to present (optional)
  - dataFormat: Exchanged data ``Format`` type
- Returns: A presentation session instance,

#### Parameters

| Name | Description |
| ---- | ----------- |
| flow | Presentation `FlowType` instance |
| docType | DocType of documents to present (optional) |
| dataFormat | Exchanged data `Format` type |

### `beginPresentation(service:)`

```swift
public func beginPresentation(service: any PresentationService) -> PresentationSession
```

Begin attestation presentation to a verifier
- Parameters:
  - service: A ``PresentationService`` instance
  - docType: DocType of documents to present (optional)
  - dataFormat: Exchanged data ``Format`` type
- Returns: A presentation session instance,

#### Parameters

| Name | Description |
| ---- | ----------- |
| service | A `PresentationService` instance |
| docType | DocType of documents to present (optional) |
| dataFormat | Exchanged data `Format` type |

### `authorizedAction(action:disabled:dismiss:localizedReason:)`

```swift
public static func authorizedAction<T>(action: () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T?
```

Perform an action after user authorization via TouchID/FaceID/Passcode
- Parameters:
  - dismiss: Action to perform if the user cancels authorization
  - action: Action to perform after user authorization
