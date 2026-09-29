# Trust Mark

Configure and retrieve EUDI Wallet Trust Mark information and display resources.

## Overview

Pass a ``TrustMarkSource`` to ``EudiWallet`` to enable its optional
``EudiWallet/trustMarkManager``. Omitting the source keeps Trust Mark support disabled.
The manager uses the wallet's injected `NetworkingProtocol` client, or `URLSession.shared`.

```swift
import EudiWalletKit
import MdocDataModel18013

let information = TrustMarkInformation(
    trustMarkResourceURL: "https://example.com/TrustMarkResource.json",
    listOfCertifiedWalletsURL: "https://example.com/certified",
    walletSolutionInfoPageURL: "https://example.com/certified?id=YOUR_WALLET_ID"
)
let wallet = try EudiWallet(
    eudiWalletConfig: configuration,
    trustConfig: trustConfiguration,
    trustMarkSource: .static(information: information)
)
if let manager = wallet.trustMarkManager {
    let trustMark = try await manager.getTrustMark()
    let imageURL = trustMark.imageURL
    let text = trustMark.resource.text.localizedValue(for: "en-GB")
    // Render the image and text, and open the two certification URLs in the browser.
}
```

For runtime configuration, implement ``TrustMarkProvider`` in the app and use
`.dynamic(provider: provider)`. Like `WalletAttestationsProvider`, the provider is
a `Sendable` protocol with an `async throws` method. The source remains in wallet kit
because it depends on this provider protocol. `TrustMark`, `TrustMarkInformation`,
and `TrustMarkResource` are `Codable`, `Equatable`, and `Sendable` data models in
`MdocDataModel18013`.

Each `getTrustMark()` call resolves the information and fetches the JSON resource.
A static source avoids the provider call, but still downloads the resource. HTTP
failures, malformed JSON, provider errors, and cancellation are surfaced to the caller.
The manager adds no persistent cache; the injected client's HTTP cache policy applies.

Image URLs may be relative to the resource URL. `TrustMark.imageURL` resolves them,
and the application renders the downloaded image format (which may be SVG).
Text selection tries the requested language tag, its base language, English, then
the first available key in sorted order. Empty localisations return `nil`.

Fetching a resource does not independently verify wallet certification. Configure
the resource and certification URLs supplied for the certified wallet solution.

