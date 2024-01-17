**CLASS**

# `EudiWallet`

**Contents**

- [Properties](#properties)
  - `storage`
  - `standard`
  - `userAuthenticationRequired`
  - `trustedReaderCertificates`
  - `verifierApiUri`
  - `vciIssuerUrl`
  - `vciClientId`
  - `vciRedirectUri`
- [Methods](#methods)
  - `init(storageType:serviceName:accessGroup:trustedReaderCertificates:userAuthenticationRequired:verifierApiUri:vciIssuerUrl:vciClientId:vciRedirectUri:)`
  - `issueDocument(docType:format:useSecureEnclave:)`
  - `beginIssueDocument(id:)`
  - `endIssueDocument(_:)`
  - `loadDocuments()`
  - `deleteDocuments()`
  - `loadSampleData(sampleDataFiles:)`
  - `prepareServiceDataParameters(docType:dataFormat:)`
  - `beginPresentation(flow:docType:dataFormat:)`
  - `beginPresentation(service:)`
  - `authorizedAction(dismiss:action:)`

```swift
public final class EudiWallet: ObservableObject
```

User wallet implementation

## Properties
### `storage`

```swift
public private(set) var storage: StorageManager
```

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

### `verifierApiUri`

```swift
public var verifierApiUri: String?
```

OpenID4VP verifier api URL (used for preregistered clients)

### `vciIssuerUrl`

```swift
public var vciIssuerUrl: String?
```

### `vciClientId`

```swift
public var vciClientId: String?
```

### `vciRedirectUri`

```swift
public var vciRedirectUri: String = "eudi-openid4ci://authorize/"
```

## Methods
### `init(storageType:serviceName:accessGroup:trustedReaderCertificates:userAuthenticationRequired:verifierApiUri:vciIssuerUrl:vciClientId:vciRedirectUri:)`

```swift
public init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true, verifierApiUri: String? = nil, vciIssuerUrl: String? = nil, vciClientId: String? = nil, vciRedirectUri: String? = nil)
```

### `issueDocument(docType:format:useSecureEnclave:)`

```swift
@discardableResult public func issueDocument(docType: String, format: DataFormat = .cbor, useSecureEnclave: Bool = false) async throws -> WalletStorage.Document
```

### `beginIssueDocument(id:)`

```swift
public func beginIssueDocument(id: String) async throws -> IssueRequest
```

Issue a document and save in wallet storage

 ** Not tested **
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

### `authorizedAction(dismiss:action:)`

```swift
public static func authorizedAction(dismiss: () -> Void, action: () async throws -> Void) async throws
```

Perform an action after user authorization via TouchID/FaceID/Passcode
- Parameters:
  - dismiss: Action to perform if the user cancels authorization
  - action: Action to perform after user authorization
