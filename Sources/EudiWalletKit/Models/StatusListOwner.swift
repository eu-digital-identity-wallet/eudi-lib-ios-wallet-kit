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

/// The credential or registration certificate whose status is being checked.
/// The status-list URL and token format do not identify the applicable trust context.
public enum StatusListOwner: Hashable, Sendable {
    /// The mdoc docType or SD-JWT vct, resolved through the configured trust mappings.
    case credential(docType: String)
    case registrationCertificate
}
