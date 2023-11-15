**CLASS**

# `StorageModel`

**Contents**

- [Properties](#properties)
  - `knownDocTypes`
  - `docTypes`
  - `mdocModels`
  - `modelIds`
  - `hasData`
  - `hasWellKnownData`
  - `docCount`
  - `mdlModel`
  - `pidModel`
  - `otherModels`
- [Methods](#methods)
  - `init(storageService:)`
  - `getTypedDoc(of:)`
  - `getTypedDocs(of:)`
  - `getDoc(index:)`
  - `getDoc(docType:)`
  - `removeDoc(docType:)`
  - `removeDoc(index:)`

```swift
public class StorageModel: ObservableObject
```

Sample data storage service

## Properties
### `knownDocTypes`

```swift
public static let knownDocTypes = [EuPidModel.EuPidDocType, IsoMdlModel.isoDocType]
```

### `docTypes`

```swift
public var docTypes: [String?] = []
```

### `mdocModels`

```swift
@Published public var mdocModels: [MdocDecodable?] = []
```

### `modelIds`

```swift
public var modelIds: [String?] = []
```

### `hasData`

```swift
@Published public var hasData: Bool = false
```

### `hasWellKnownData`

```swift
@Published public var hasWellKnownData: Bool = false
```

### `docCount`

```swift
@Published public var docCount: Int = 0
```

### `mdlModel`

```swift
@Published public var mdlModel: IsoMdlModel?
```

### `pidModel`

```swift
@Published public var pidModel: EuPidModel?
```

### `otherModels`

```swift
@Published public var otherModels: [GenericMdocModel] = []
```

## Methods
### `init(storageService:)`

```swift
public init(storageService: any DataStorageService)
```

### `getTypedDoc(of:)`

```swift
public func getTypedDoc<T>(of: T.Type = T.self) -> T? where T: MdocDecodable
```

### `getTypedDocs(of:)`

```swift
public func getTypedDocs<T>(of: T.Type = T.self) -> [T] where T: MdocDecodable
```

### `getDoc(index:)`

```swift
public func getDoc(index: Int) -> MdocDecodable?
```

### `getDoc(docType:)`

```swift
public func getDoc(docType: String) -> MdocDecodable?
```

### `removeDoc(docType:)`

```swift
public func removeDoc(docType: String)
```

### `removeDoc(index:)`

```swift
public func removeDoc(index: Int)
```
