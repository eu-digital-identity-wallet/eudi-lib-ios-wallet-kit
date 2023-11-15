**CLASS**

# `EudiWallet`

**Contents**

- [Properties](#properties)
  - `storage`
  - `standard`
  - `userAuthenticationRequired`
  - `trustedReaderCertificates`
  - `openId4VpVerifierApiUri`
- [Methods](#methods)
  - `init(storageType:serviceName:accessGroup:trustedReaderCertificates:userAuthenticationRequired:)`
  - `issueDocument(id:issuer:)`
  - `loadDocuments()`
  - `loadSampleData(sampleDataFiles:)`
  - `beginPresentation(flow:docType:dataFormat:)`
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

### `openId4VpVerifierApiUri`

```swift
public var openId4VpVerifierApiUri: String?
```

OpenID4VP verifier api URL (used for preregistered clients)

## Methods
### `init(storageType:serviceName:accessGroup:trustedReaderCertificates:userAuthenticationRequired:)`

```swift
public init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true)
```

### `issueDocument(id:issuer:)`

```swift
public func issueDocument(id: String, issuer: (_ send: IssueRequest) async throws -> WalletStorage.Document) async throws
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

### `loadDocuments()`

```swift
@discardableResult public func loadDocuments() -> [WalletStorage.Document]?
```

Load documents from storage

Calls ``storage`` loadDocuments
- Returns: An array of ``WalletStorage.Document`` objects

### `loadSampleData(sampleDataFiles:)`

```swift
public func loadSampleData(sampleDataFiles: [String]? = nil) throws
```

Load sample data from json files

The mdoc data are stored in wallet storage as documents
- Parameter sampleDataFiles: Names of sample files provided in the app bundle

#### Parameters

| Name | Description |
| ---- | ----------- |
| sampleDataFiles | Names of sample files provided in the app bundle |

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

### `authorizedAction(dismiss:action:)`

```swift
public static func authorizedAction(dismiss: () -> Void, action: () async throws -> Void) async throws
```

Perform an action after user authorization via TouchID/FaceID/Passcode
- Parameters:
  - dismiss: Action to perform if the user cancels authorization
  - action: Action to perform after user authorization
