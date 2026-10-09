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

/// Authentication of the current presentation request, distinct from certificate trust
/// and relying-party registration policy warnings.
public enum ReaderAuthenticationStatus: Sendable, Equatable {
    /// Authentication has not completed or no authentication result is available.
    case notEvaluated
    /// The request passed the authentication required by its client identifier scheme.
    case authenticated
    /// The request failed validation or required authentication was not established.
    case failed
    /// An explicitly supported flow, such as plain redirect URI, requires no reader authentication.
    case notApplicable
}
