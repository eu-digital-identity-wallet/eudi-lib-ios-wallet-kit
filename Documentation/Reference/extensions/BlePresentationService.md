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

### `didFinishedWithError(_:)`

```swift
public func didFinishedWithError(_ error: Error)
```

### `didReceiveRequest(_:handleSelected:)`

```swift
public func didReceiveRequest(_ request: [String : Any], handleSelected: @escaping (Bool, MdocDataTransfer18013.RequestItems?) -> Void)
```
