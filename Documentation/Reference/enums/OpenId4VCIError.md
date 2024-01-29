**ENUM**

# `OpenId4VCIError`

**Contents**

- [Cases](#cases)
  - `authRequestFailed(_:)`
  - `authorizeResponseNoUrl`
  - `authorizeResponseNoCode`
  - `tokenRequestFailed(_:)`
  - `tokenResponseNoData`
  - `tokenResponseInvalidData(_:)`
  - `dataNotValid`
- [Properties](#properties)
  - `localizedDescription`

```swift
public enum OpenId4VCIError: LocalizedError
```

## Cases
### `authRequestFailed(_:)`

```swift
case authRequestFailed(Error)
```

### `authorizeResponseNoUrl`

```swift
case authorizeResponseNoUrl
```

### `authorizeResponseNoCode`

```swift
case authorizeResponseNoCode
```

### `tokenRequestFailed(_:)`

```swift
case tokenRequestFailed(Error)
```

### `tokenResponseNoData`

```swift
case tokenResponseNoData
```

### `tokenResponseInvalidData(_:)`

```swift
case tokenResponseInvalidData(String)
```

### `dataNotValid`

```swift
case dataNotValid
```

## Properties
### `localizedDescription`

```swift
public var localizedDescription: String
```
