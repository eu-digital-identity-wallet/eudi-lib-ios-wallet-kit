**CLASS**

# `FaultPresentationService`

**Contents**

- [Properties](#properties)
  - `status`
  - `flow`
- [Methods](#methods)
  - `init(msg:)`
  - `init(error:)`
  - `startQrEngagement()`
  - `receiveRequest()`
  - `sendResponse(userAccepted:itemsToSend:onSuccess:)`

```swift
public class FaultPresentationService: PresentationService
```

Fault presentation service. Used to communicate error state to the user

## Properties
### `status`

```swift
public var status: TransferStatus = .error
```

### `flow`

```swift
public var flow: FlowType = .other
```

## Methods
### `init(msg:)`

```swift
public init(msg: String)
```

### `init(error:)`

```swift
public init(error: Error)
```

### `startQrEngagement()`

```swift
public func startQrEngagement() async throws -> String?
```

### `receiveRequest()`

```swift
public func receiveRequest() async throws -> [String : Any]
```

### `sendResponse(userAccepted:itemsToSend:onSuccess:)`

```swift
public func sendResponse(userAccepted: Bool, itemsToSend: RequestItems,  onSuccess: ((URL?) -> Void)?) async throws
```

#### Parameters

| Name | Description |
| ---- | ----------- |
| userAccepted | True if user accepted to send the response |
| itemsToSend | The selected items to send organized in document types and namespaces (see `RequestItems`) |