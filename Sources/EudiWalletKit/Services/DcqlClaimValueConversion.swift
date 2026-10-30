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

import Foundation
import OpenID4VP
import SwiftCBOR
import SwiftyJSON

/// Keep credential values typed; display descriptions are unsuitable for matching.
enum DcqlClaimValueConversion {
  static func fromCbor(_ value: CBOR) -> DCQLClaimValue? {
    switch value {
    case .boolean(let value): return .boolean(value)
    case .utf8String(let value): return .string(value)
    case .unsignedInt(let value): return Int64(exactly: value).map(DCQLClaimValue.integer)
    case .negativeInt(let value):
      return Int64(exactly: value).map { .integer(-1 - $0) }
    case .byteString(let bytes): return .string(base64Url(bytes))
    case .half(let value), .float(let value):
      return Int64(exactly: value).map(DCQLClaimValue.integer)
    case .double(let value): return Int64(exactly: value).map(DCQLClaimValue.integer)
    case .date(let value): return fromCbor(.double(value.timeIntervalSince1970))
    case .tagged(let tag, let content):
      // RFC 8949 section 6.1 gives these tags special JSON string encodings.
      switch tag.rawValue {
      case 2, 3, 21, 22, 23:
        guard case .byteString(let bytes) = content else { return nil }
        switch tag.rawValue {
        case 3: return .string("~" + base64Url(bytes))
        case 22: return .string(Data(bytes).base64EncodedString())
        case 23: return .string(bytes.map { String(format: "%02x", $0) }.joined())
        default: return .string(base64Url(bytes))
        }
      default: return fromCbor(content)
      }
    default: return nil
    }
  }

  private static func base64Url(_ bytes: [UInt8]) -> String {
    Data(bytes).base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  static func fromJson(_ root: JSON, at path: ClaimPath) -> [DCQLClaimValue] {
    var selected = [root]
    for element in path.value {
      switch element {
      case .claim(let name): selected = selected.compactMap { $0.dictionary?[name] }
      case .arrayElement(let index):
        selected = selected.compactMap { value in
          guard let array = value.array, array.indices.contains(index) else { return nil }
          return array[index]
        }
      case .allArrayElements: selected = selected.flatMap { $0.array ?? [] }
      }
    }
    return selected.compactMap { value in
      guard let data = try? JSONSerialization.data(withJSONObject: value.object, options: [.fragmentsAllowed]) else { return nil }
      return try? JSONDecoder().decode(DCQLClaimValue.self, from: data)
    }
  }
}
