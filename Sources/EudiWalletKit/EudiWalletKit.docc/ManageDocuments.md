#  Manage documents

The EudiWallet class provides a set of methods to work with documents.

### Loading documents

The ``EudiWallet/loadDocuments(status:)`` method returns documents with a specific status from storage.

The following example shows how to retrieve issued documents:

```swift
 public func loadDocuments() async throws {
		let documents = try await wallet.loadDocuments(status: .issued)
	}
```

To load documents of all statuses use the ``EudiWallet/loadAllDocuments()`` method.

```swift
let documents = try await wallet.loadAllDocuments()
```

The ``EudiWallet/loadDocument(id:status:)`` method returns a document with a given id and status. 

The following example shows how to retrieve a document:

```swift
let document = try await wallet.loadDocument(id: documentId, status: .issued)
```


### Storage manager
The read-only property ``storage`` is an instance of a ``StorageManager`` class.
Currently the keychain implementation is used. It provides document management functionality using the iOS KeyChain.

The storage model provides the following models for the supported well-known document types:

|DocType|Model|
|-------|-----|
|eu.europa.ec.eudiw.pid.1|[EuPidModel](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/eupidmodel)|
|org.iso.18013.5.1.mDL|[IsoMdlModel](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/isomdlmodel)|

Since the issued mDoc documents retrieved expose only basic metadata and the raw data, they must be decoded to the corresponding CBOR models. The library provides the ``StorageManager/toClaimsModel(doc:modelFactory:)`` function to decode document raw CBOR data to strongly-typed models conforming to [DocClaimsDecodable](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/DocClaimsDecodable) protocol. 

The loading functions automatically update the ``StorageManager`` members. The decoded issued documents are available in the ``StorageManager/docModels`` property. The deferred and pending documents are available in the ``StorageManager/deferredDocuments`` and ``StorageManager/pendingDocuments`` properties respectively.

For other document types the [GenericMdocModel](https://eu-digital-identity-wallet.github.io/eudi-lib-ios-iso18013-data-model/documentation/mdocdatamodel18013/genericmdocmodel) is provided.


### Deleting a document

The ``EudiWallet/deleteDocument(id:status:)`` method that deletes a document with the given id.

The following example shows how to delete a document:

```swift
try await wallet.deleteDocument(id: documentId, status: .issued)
```
To delete all documents you can use ``EudiWallet/deleteAllDocuments()``
