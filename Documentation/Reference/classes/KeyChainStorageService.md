**CLASS**

# `KeyChainStorageService`

**Contents**

- [Properties](#properties)
  - `defaultId`
  - `vcService`
  - `accessGroup`
  - `itemTypeCode`
- [Methods](#methods)
  - `init()`
  - `loadDocument(id:)`
  - `saveDocument(id:value:)`
  - `deleteDocument(id:)`

```swift
public class KeyChainStorageService: DataStorageService
```

## Properties
### `defaultId`

```swift
public static var defaultId: String = "eudiw"
```

### `vcService`

```swift
var vcService = "eudiw"
```

### `accessGroup`

```swift
var accessGroup: String?
```

### `itemTypeCode`

```swift
var itemTypeCode: Int?
```

## Methods
### `init()`

```swift
public init()
```

### `loadDocument(id:)`

```swift
public func loadDocument(id: String) throws -> Data
```

Gets the secret with the id passed in parameter
- Parameters:
  - id: The Id of the secret
  - itemTypeCode: the item type code for the secret
  - accessGroup: the access group for the secret
- Returns: The secret

#### Parameters

| Name | Description |
| ---- | ----------- |
| id | The Id of the secret |
| itemTypeCode | the item type code for the secret |
| accessGroup | the access group for the secret |

### `saveDocument(id:value:)`

```swift
public func saveDocument(id: String, value: inout Data) throws
```

Save the secret to keychain
Note: the value passed in will be zeroed out after the secret is saved
- Parameters:
  - id: The Id of the secret
  - itemTypeCode: The secret type code (4 chars)
  - accessGroup: The access group to use to save secret.
  - value: The value of the secret

#### Parameters

| Name | Description |
| ---- | ----------- |
| id | The Id of the secret |
| itemTypeCode | The secret type code (4 chars) |
| accessGroup | The access group to use to save secret. |
| value | The value of the secret |

### `deleteDocument(id:)`

```swift
public func deleteDocument(id: String) throws
```

Delete the secret from keychain
Note: the value passed in will be zeroed out after the secret is deleted
- Parameters:
  - id: The Id of the secret
  - itemTypeCode: The secret type code (4 chars)
  - accessGroup: The access group of the secret.

#### Parameters

| Name | Description |
| ---- | ----------- |
| id | The Id of the secret |
| itemTypeCode | The secret type code (4 chars) |
| accessGroup | The access group of the secret. |