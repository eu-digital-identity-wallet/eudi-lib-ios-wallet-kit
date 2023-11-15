**EXTENSION**

# `BlePresentationService`
```swift
extension BlePresentationService: MdocOfflineDelegate
```

## Methods
### `didChangeStatus(_:)`

```swift
public func didChangeStatus(_ newStatus: MdocDataTransfer18013.TransferStatus)
```

BLE transfer changed status
- Parameter newStatus: New status

#### Parameters

| Name | Description |
| ---- | ----------- |
| newStatus | New status |

### `didFinishedWithError(_:)`

```swift
public func didFinishedWithError(_ error: Error)
```

Transfer finished with error
- Parameter error: The error description

#### Parameters

| Name | Description |
| ---- | ----------- |
| error | The error description |

### `didReceiveRequest(_:handleSelected:)`

```swift
public func didReceiveRequest(_ request: [String : Any], handleSelected: @escaping (Bool, MdocDataTransfer18013.RequestItems?) -> Void)
```

Received request handler
- Parameters:
  - request: Request items keyed by §UserRequestKeys§
  - handleSelected: Callback function to call after user selection of items to send

#### Parameters

| Name | Description |
| ---- | ----------- |
| request | Request items keyed by §UserRequestKeys§ |
| handleSelected | Callback function to call after user selection of items to send |