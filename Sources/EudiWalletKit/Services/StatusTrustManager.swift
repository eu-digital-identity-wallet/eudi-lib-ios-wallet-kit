/*
Copyright (c) 2026 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#if canImport(EudiEtsi1196x2)
import Foundation
import EudiEtsi1196x2
import MdocSecurity18013
import os

/// Configuration-owned storage, bounded by context pairs rather than arbitrary document types.
final class StatusTrustManagerCache: Sendable {
    private struct Contexts: Hashable {
        let primary: EtsiContextType?
        let fallback: EtsiContextType?
    }

    private let source: TrustSource
    private let fallback: TrustSource?
    private let managers = OSAllocatedUnfairLock(initialState: [Contexts: StatusTrustManager]())

    init(source: TrustSource, fallback: TrustSource?) {
        self.source = source
        self.fallback = fallback
    }

    func manager(for owner: StatusListOwner?) -> StatusTrustManager {
        func context(for source: TrustSource) -> EtsiContextType? {
            switch owner {
            case .credential(let docType): (source.contextTypeMappings ?? .default)[docType]?.statusContext
            case .registrationCertificate: .wrprcStatus
            case nil: nil
            }
        }
        let contexts = Contexts(primary: context(for: source), fallback: fallback.flatMap { context(for: $0) })
        return managers.withLock { managers in
            if let manager = managers[contexts] { return manager }
            let manager = StatusTrustManager(source: source, context: contexts.primary,
                fallback: fallback, fallbackContext: contexts.fallback)
            managers[contexts] = manager
            return manager
        }
    }
}

/// Owns the underlying LoTE cache without allowing callers to change its verification context.
actor StatusTrustManager: CertificateTrustValidator {
    private let manager: EtsiTrustManager
    private nonisolated let context: EtsiContextType?
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(source: TrustSource, context: EtsiContextType?, fallback: TrustSource?, fallbackContext: EtsiContextType?) {
        self.context = context
        let fallbackManager = fallback.map {
            EtsiTrustManager(source: $0.withContextTypeMappings(nil),
                defaultVerificationContext: fallbackContext?.verificationContext)
        }
        manager = EtsiTrustManager(source: source.withContextTypeMappings(nil),
            defaultVerificationContext: context?.verificationContext, fallback: fallbackManager)
    }

    // The protocol's mutable document selector must not override this fixed status context.
    nonisolated var docType: String? {
        get { nil }
        set { }
    }

    nonisolated func getVerificationContext() -> (any VerificationContext)? {
        context?.verificationContext
    }

    func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) {
        await acquire()
        defer { release() }
        guard !Task.isCancelled else { return (false, "Status trust validation cancelled") }
        return await manager.validateCertTrustPath(chain: chain)
    }

    func createCertTrustPath(chain: [Data]) async -> [Data]? {
        await acquire()
        defer { release() }
        guard !Task.isCancelled else { return nil }
        return await manager.createCertTrustPath(chain: chain)
    }

    // Actor isolation alone permits reentrancy across validation's awaits. Keep the entire
    // operation exclusive: the dependency writes fallback.docType and updates its LoTE cache.
    private func acquire() async {
        if busy {
            await withCheckedContinuation { waiters.append($0) }
        } else {
            busy = true
        }
    }

    private func release() {
        if waiters.isEmpty { busy = false }
        else { waiters.removeFirst().resume() }
    }
}
#endif
