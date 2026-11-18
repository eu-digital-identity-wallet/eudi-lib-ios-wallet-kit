# Checking document status

Pass the owning credential's mdoc `docType` or SD-JWT `vct` when checking its status:

```swift
let status = try await wallet.getDocumentStatus(for: statusList, docType: documentType)
```

For direct service use, pass `owner: .credential(docType: documentType)` to `DocumentStatusService`. WRPRC checks in issuance and presentation automatically use `.registrationCertificate`.

ETSI trust resolves the document type through the trust source's context mappings, or the default mappings when none are configured. PID uses `PIDStatus`, mDL uses `EAAStatus` with the mDL use case, qualified EAA uses `QEAAStatus`, and public EAA uses `PubEAAStatus`. WRPRC uses `WalletRelyingPartyRegistrationCertificateStatus`. A fallback trust source uses its own mappings and status anchors.

Existing calls that omit the document type still compile, but cannot establish ETSI status trust under the default `.enforce` policy. Unknown types also fail; add them to `contextTypeMappings`. The explicit `.warning` policy continues to allow certificate-chain trust failures after cryptographic signature verification. Platform SecTrust behavior is unchanged.

For static trust sources with `anchorsPerContext`, configure status anchors separately using `.pidStatus`, `.mdlStatus`, `.qeaaStatus`, `.pubEaaStatus` or `.wrprcStatus`. The `rootCertificates` convenience initializer applies its anchors to every context, including status contexts. WRPAC-only anchors do not authorize status signers.

Verified status tokens are cached separately for each owner, token format and trust configuration, even when status-list URLs coincide.
