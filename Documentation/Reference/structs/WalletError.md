**STRUCT**

# `WalletError`

**Contents**

- [Properties](#properties)
  - `errorDescription`
- [Methods](#methods)
  - `init(key:code:)`
  - `init(description:code:userInfo:)`
  - `==(_:_:)`

```swift
public struct WalletError: LocalizedError
```

Wallet error

## Properties
### `errorDescription`

```swift
public var errorDescription: String?
```

## Methods
### `init(key:code:)`

```swift
public init(key: String, code: Int = 0)
```

### `init(description:code:userInfo:)`

```swift
public init(description: String, code: Int = 0, userInfo: [String: Any]? = nil)
```

### `==(_:_:)`

```swift
public static func ==(lhs: Self, rhs: Self) -> Bool
```
