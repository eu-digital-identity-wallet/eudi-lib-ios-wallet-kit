**PROTOCOL**

# `DataStorageService`

```swift
public protocol DataStorageService
```

## Properties
### `defaultId`

```swift
static var defaultId: String
```

## Methods
### `loadDocument(id:)`

```swift
func loadDocument(id: String) throws -> Data
```

### `saveDocument(id:value:)`

```swift
func saveDocument(id: String, value: inout Data) throws
```

### `deleteDocument(id:)`

```swift
func deleteDocument(id: String) throws
```
