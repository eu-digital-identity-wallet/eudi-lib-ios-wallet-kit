**ENUM**

# `FlowType`

**Contents**

- [Cases](#cases)
  - `ble`
  - `openid4vp(qrCode:)`
  - `other`
- [Properties](#properties)
  - `isProximity`
  - `qrCode`

```swift
public enum FlowType: Codable, Hashable
```

Data exchange flow type

## Cases
### `ble`

```swift
case ble
```

### `openid4vp(qrCode:)`

```swift
case openid4vp(qrCode: Data)
```

### `other`

```swift
case other
```

## Properties
### `isProximity`

```swift
public var isProximity: Bool
```

True if proximity flow type (currently ``ble``)

### `qrCode`

```swift
public var qrCode: Data?
```
