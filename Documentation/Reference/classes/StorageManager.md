**CLASS**

# `StorageManager`

**Contents**

- [Properties](#properties)
  - `knownDocTypes`
  - `docTypes`
  - `mdocModels`
  - `documentIds`
  - `hasData`
  - `hasWellKnownData`
  - `docCount`
  - `mdlModel`
  - `pidModel`
  - `otherModels`
  - `uiError`
- [Methods](#methods)
  - `init(storageService:)`
  - `loadDocuments()`
  - `getDocumentModel(index:)`
  - `getDocumentModel(docType:)`
  - `deleteDocument(docType:)`
  - `deleteDocument(index:)`
  - `deleteDocuments()`

```swift
public class StorageManager: ObservableObject
```

Storage manager. Provides services and view models

## Properties
### `knownDocTypes`

```swift
public static let knownDocTypes = [EuPidModel.euPidDocType, IsoMdlModel.isoDocType]
```

### `docTypes`

```swift
public var docTypes: [String?] = []
```

Array of doc.types of documents loaded in the wallet

### `mdocModels`

```swift
@Published public var mdocModels: [MdocDecodable?] = []
```

Array of document models loaded in the wallet

### `documentIds`

```swift
public var documentIds: [String?] = []
```

Array of document identifiers loaded in the wallet

### `hasData`

```swift
@Published public var hasData: Bool = false
```

Whether wallet currently has loaded data

### `hasWellKnownData`

```swift
@Published public var hasWellKnownData: Bool = false
```

Whether wallet currently has loaded a document with doc.type included in the ``knownDocTypes`` array

### `docCount`

```swift
@Published public var docCount: Int = 0
```

Count of documents loaded in the wallet

### `mdlModel`

```swift
@Published public var mdlModel: IsoMdlModel?
```

The driver license model loaded in the wallet

### `pidModel`

```swift
@Published public var pidModel: EuPidModel?
```

The PID model loaded in the wallet

### `otherModels`

```swift
@Published public var otherModels: [GenericMdocModel] = []
```

Other document models loaded in the wallet

### `uiError`

```swift
@Published public var uiError: WalletError?
```

Error object with localized message

## Methods
### `init(storageService:)`

```swift
public init(storageService: any DataStorageService)
```

### `loadDocuments()`

```swift
@discardableResult public func loadDocuments() async throws -> [WalletStorage.Document]?
```

Load documents from storage

Internally sets the ``docTypes``, ``mdocModels``, ``documentIds``, ``mdocModels``,  ``mdlModel``, ``pidModel`` variables
- Returns: An array of ``WalletStorage.Document`` objects

### `getDocumentModel(index:)`

```swift
public func getDocumentModel(index: Int) -> MdocDecodable?
```

Get document model by index
- Parameter index: Index in array of loaded models
- Returns: The ``MdocDecodable`` model

#### Parameters

| Name | Description |
| ---- | ----------- |
| index | Index in array of loaded models |

### `getDocumentModel(id:)`

```swift
public func getDocumentModel(id: String) -> MdocDecodable?
```

Get document model by id
- Parameter id: The id of the document model to return
- Returns: The ``MdocDecodable`` model

#### Parameters

| Name | Description |
| ---- | ----------- |
| id | The id of the document model to return |

### `getDocumentModels(docType:)`

```swift
public func getDocumentModels(docType: String) -> [MdocDecodable]
```

Get document model by docType
- Parameter docType: The docType of the document model to return
- Returns: The ``MdocDecodable`` model

#### Parameters

| Name | Description |
| ---- | ----------- |
| docType | The docType of the document model to return |

### `deleteDocuments(docType:)`

```swift
public func deleteDocuments(docType: String) async throws
```

Delete documents by docType
- Parameter docType: Document type

#### Parameters

| Name | Description |
| ---- | ----------- |
| docType | Document type |

### `deleteDocument(id:)`

```swift
public func deleteDocument(id: String) async throws
```

Delete document by id
- Parameter id: Document id

#### Parameters

| Name | Description |
| ---- | ----------- |
| id | Document id |

### `deleteDocument(index:)`

```swift
public func deleteDocument(index: Int) async throws
```

Delete document by Index
- Parameter index: Index in array of loaded models

#### Parameters

| Name | Description |
| ---- | ----------- |
| index | Index in array of loaded models |

### `deleteDocuments()`

```swift
public func deleteDocuments() async throws
```

Delete documenmts
