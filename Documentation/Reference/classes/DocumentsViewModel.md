**CLASS**

# `DocumentsViewModel`

**Contents**

- [Properties](#properties)
  - `knownDocTypes`
  - `mdocModels`
  - `modelIds`
  - `storageService`
  - `hasData`
  - `docCount`
  - `logger`
- [Methods](#methods)
  - `init(storageService:)`
  - `loadDocuments()`
  - `getDoc(i:)`
  - `removeDoc(i:)`

```swift
public class DocumentsViewModel: ObservableObject
```

Sample data storage service

## Properties
### `knownDocTypes`

```swift
public static let knownDocTypes = [EuPidModel.EuPidDocType, IsoMdlModel.isoDocType]
```

### `mdocModels`

```swift
@Published  public var mdocModels: [MdocDecodable?] = []
```

### `modelIds`

```swift
public var modelIds: [String?] = []
```

### `storageService`

```swift
var storageService: any DataStorageService
```

### `hasData`

```swift
@Published public var hasData: Bool = false
```

### `docCount`

```swift
@Published public var docCount: Int = 0
```

### `logger`

```swift
let logger: Logger
```

## Methods
### `init(storageService:)`

```swift
public init(storageService: any DataStorageService)
```

### `loadDocuments()`

```swift
func loadDocuments()
```

### `getDoc(i:)`

```swift
public func getDoc(i: Int) -> MdocDecodable?
```

### `removeDoc(i:)`

```swift
public func removeDoc(i: Int)
```
