**CLASS**

# `EudiWallet`

**Contents**

- [Properties](#properties)
  - `storageService`
  - `documentsViewModel`
- [Methods](#methods)
  - `init(storageType:)`
  - `issueDocument(id:issuer:)`
  - `loadSampleData(sampleDataFiles:)`
  - `beginPresentation(flow:dataFormat:)`

```swift
public class EudiWallet: ObservableObject
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

## Methods
### `init(storageType:)`

```swift
public init(storageType: StorageType = .keyChain)
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