**ENUM**

# `FlowType`

**Contents**

- [Cases](#cases)
  - `ble`
  - `openid4vp(qrCode:)`
- [Properties](#properties)
  - `isProximity`

```swift
public enum FlowType: Codable, Hashable
```

## Cases
### `ble`

```swift
case ble
```

### `openid4vp(qrCode:)`

```swift
case openid4vp(qrCode: Data)
```

## Properties
### `isProximity`

```swift
public var isProximity: Bool
```
