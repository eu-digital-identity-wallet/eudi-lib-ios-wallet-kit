**CLASS**

# `EudiWallet`

**Contents**

- [Properties](#properties)
  - `storageService`
  - `documentsViewModel`
  - `standard`
  - `userAuthenticationRequired`
  - `trustedReaderCertificates`
- [Methods](#methods)
  - `init(storageType:serviceName:accessGroup:trustedReaderCertificates:userAuthenticationRequired:)`
  - `issueDocument(id:issuer:)`
  - `loadSampleData(sampleDataFiles:)`
  - `beginPresentation(flow:dataFormat:)`
  - `authorizedAction(isFallBack:dismiss:action:)`

```swift
public final class EudiWallet: ObservableObject
```

User wallet implementation

## Properties
### `storageService`

```swift
var storageService: any DataStorageService
```

### `documentsViewModel`

```swift
public var documentsViewModel: DocumentsViewModel
```

### `standard`

```swift
public static private(set) var standard: EudiWallet = EudiWallet()
```

### `userAuthenticationRequired`

```swift
public var userAuthenticationRequired: Bool
```

### `trustedReaderCertificates`

```swift
public var trustedReaderCertificates: [Data]?
```

## Methods
### `init(storageType:serviceName:accessGroup:trustedReaderCertificates:userAuthenticationRequired:)`

```swift
init(storageType: StorageType = .keyChain, serviceName: String = "eudiw", accessGroup: String? = nil, trustedReaderCertificates: [Data]? = nil, userAuthenticationRequired: Bool = true)
```

### `issueDocument(id:issuer:)`

```swift
public func issueDocument(id: String, issuer: (_ send: IssueRequest) async throws -> WalletStorage.Document) async throws
```

### `loadSampleData(sampleDataFiles:)`

```swift
public func loadSampleData(sampleDataFiles: [String]? = nil) throws
```

### `beginPresentation(flow:dataFormat:)`

```swift
public func beginPresentation(flow: FlowType, dataFormat: DataFormat = .cbor) -> PresentationSession
```

Begin attestation presentation to a verifier
- Parameters:
  - flow: Presentation ``FlowType`` instance
  - dataFormat: Exchanged data ``Format`` type
- Returns: A presentation session instance,

#### Parameters

| Name | Description |
| ---- | ----------- |
| flow | Presentation `FlowType` instance |
| dataFormat | Exchanged data `Format` type |

### `authorizedAction(isFallBack:dismiss:action:)`

```swift
public static func authorizedAction(isFallBack: Bool = false, dismiss: () -> Void, action: () async throws -> Void) async throws
```
