**CLASS**

# `DataSampleStorageService`

**Contents**

- [Properties](#properties)
  - `euPidModel`
  - `isoMdlModel`
  - `sampleData`
  - `pidLoaded`
  - `mdlLoaded`
  - `debugDisplay`
  - `logger`
  - `hasData`
  - `defaultId`
- [Methods](#methods)
  - `init()`
  - `getDoc(i:)`
  - `removeDoc(i:)`
  - `loadSampleData(force:)`
  - `loadDocument(id:)`
  - `saveDocument(id:value:)`
  - `deleteDocument(id:)`

```swift
public class DataSampleStorageService: ObservableObject, DataStorageService
```

## Properties
### `euPidModel`

```swift
@Published public var euPidModel: EuPidModel?
```

### `isoMdlModel`

```swift
@Published public var isoMdlModel: IsoMdlModel?
```

### `sampleData`

```swift
var sampleData: Data?
```

### `pidLoaded`

```swift
@AppStorage("pidLoaded") public var pidLoaded: Bool = false
```

### `mdlLoaded`

```swift
@AppStorage("mdlLoaded") public var mdlLoaded: Bool = false
```

### `debugDisplay`

```swift
@AppStorage("DebugDisplay") var debugDisplay: Bool = false
```

### `logger`

```swift
let logger: Logger
```

### `hasData`

```swift
public var hasData: Bool
```

### `defaultId`

```swift
public static var defaultId: String = "EUDI_sample_data"
```

## Methods
### `init()`

```swift
public init()
```

### `getDoc(i:)`

```swift
public func getDoc(i: Int) -> MdocDecodable?
```

### `removeDoc(i:)`

```swift
public func removeDoc(i: Int)
```

### `loadSampleData(force:)`

```swift
public func loadSampleData(force: Bool = false)
```

### `loadDocument(id:)`

```swift
public func loadDocument(id: String) throws -> Data
```

### `saveDocument(id:value:)`

```swift
public func saveDocument(id: String, value: inout Data) throws
```

### `deleteDocument(id:)`

```swift
public func deleteDocument(id: String) throws
```
