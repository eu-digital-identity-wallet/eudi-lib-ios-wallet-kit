**STRUCT**

# `WalletError`

**Contents**

- [Properties](#properties)
  - `errorDescription`
- [Methods](#methods)
  - `init(key:code:)`
  - `init(description:code:)`
  - `==(_:_:)`

```swift
public struct WalletError: LocalizedError
```

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

### `init(description:code:)`

```swift
public init(description: String, code: Int = 0)
```

### `==(_:_:)`

```swift
public static func ==(lhs: Self, rhs: Self) -> Bool
```
