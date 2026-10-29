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

import Testing
import Foundation
import OpenID4VP
import SwiftCBOR
import SwiftyJSON
@testable import EudiWalletKit

struct DcqlClaimValueTests {
  @Test func proofOfAgeQuerySelectsOnlyBooleanTrueCredential() throws {
    let data = Data(#"{"credentials":[{"id":"age-over-18-mdoc","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.av.1"},"claims":[{"path":["eu.europa.ec.av.1","age_over_18"],"values":[true]}]}]}"#.utf8)
    let query = try JSONDecoder().decode(DCQL.self, from: data)
    let path = ClaimPath([.claim(name: "eu.europa.ec.av.1"), .claim(name: "age_over_18")])
    let queryable = DefaultDcqlQueryable(
      credentials: ["adult": ("eu.europa.ec.av.1", .cbor), "minor": ("eu.europa.ec.av.1", .cbor), "text": ("eu.europa.ec.av.1", .cbor)],
      claimPaths: ["adult": [path], "minor": [path], "text": [path]],
      claimValues: ["adult": [path: [.boolean(true)]], "minor": [path: [.boolean(false)]], "text": [path: [.string("true")]]])
    let selected = try OpenId4VpUtils.resolveDcql(query, queryable: queryable)
    #expect(selected.count == 1)
    #expect(selected.values.first?.first?.credentialId == "adult")
  }

  @Test func matchingPreservesTypeAndValue() {
    let path = ClaimPath([.claim(name: "eu.europa.ec.av.1"), .claim(name: "age_over_18")])
    let queryable = DefaultDcqlQueryable(
      credentials: ["age": ("eu.europa.ec.av.1", .cbor)],
      claimPaths: ["age": [path]],
      claimValues: ["age": [path: [.boolean(true)]]])
    #expect(queryable.hasClaimWithValue(id: "age", claimPath: path, values: [.boolean(true)]))
    #expect(!queryable.hasClaimWithValue(id: "age", claimPath: path, values: [.boolean(false)]))
    #expect(!queryable.hasClaimWithValue(id: "age", claimPath: path, values: [.string("true"), .integer(1)]))
    #expect(!queryable.hasClaimWithValue(id: "missing", claimPath: path, values: [.boolean(true)]))
  }

  @Test func integerAndWildcardMatchingRemainStrict() {
    let stored = ClaimPath([.claim(name: "items"), .arrayElement(index: 0), .claim(name: "age")])
    let wildcard = ClaimPath([.claim(name: "items"), .allArrayElements, .claim(name: "age")])
    let queryable = DefaultDcqlQueryable(
      credentials: ["age": ("example", .sdjwt)], claimPaths: ["age": [stored]],
      claimValues: ["age": [stored: [.integer(18)]]])
    #expect(queryable.hasClaimWithValue(id: "age", claimPath: wildcard, values: [.integer(18)]))
    #expect(!queryable.hasClaimWithValue(id: "age", claimPath: wildcard, values: [.string("18")]))
    #expect(!queryable.hasClaimWithValue(id: "age", claimPath: wildcard, values: [.integer(19)]))
    #expect(!queryable.hasClaimWithValue(id: "age", claimPath: .claim("missing"), values: [.integer(18)]))
  }

  @Test func cborScalarsPreserveTypesAndIntegerBoundaries() {
    #expect(DcqlClaimValueConversion.fromCbor(.boolean(true)) == .boolean(true))
    #expect(DcqlClaimValueConversion.fromCbor(.utf8String("true")) == .string("true"))
    #expect(DcqlClaimValueConversion.fromCbor(.unsignedInt(18)) == .integer(18))
    #expect(DcqlClaimValueConversion.fromCbor(.negativeInt(17)) == .integer(-18))
    #expect(DcqlClaimValueConversion.fromCbor(.negativeInt(UInt64(Int64.max))) == .integer(Int64.min))
    #expect(DcqlClaimValueConversion.fromCbor(.unsignedInt(UInt64.max)) == nil)
    #expect(DcqlClaimValueConversion.fromCbor(.negativeInt(UInt64.max)) == nil)
    #expect(DcqlClaimValueConversion.fromCbor(.null) == nil)
    #expect(DcqlClaimValueConversion.fromCbor(.array([.boolean(true)])) == nil)
  }

  @Test func cborJsonConversionHandlesTagsBytesAndIntegralFloats() {
    #expect(DcqlClaimValueConversion.fromCbor(.tagged(.standardDateTimeString, .utf8String("2026-10-03"))) == .string("2026-10-03"))
    #expect(DcqlClaimValueConversion.fromCbor(.byteString([0xfb, 0xff])) == .string("-_8"))
    #expect(DcqlClaimValueConversion.fromCbor(.tagged(.negativeBignum, .byteString([1]))) == .string("~AQ"))
    #expect(DcqlClaimValueConversion.fromCbor(.tagged(.expectedConversionToBase64Encoding, .byteString([1]))) == .string("AQ=="))
    #expect(DcqlClaimValueConversion.fromCbor(.tagged(.expectedConversionToBase16Encoding, .byteString([0xfb, 0xff]))) == .string("fbff"))
    #expect(DcqlClaimValueConversion.fromCbor(.double(18)) == .integer(18))
    #expect(DcqlClaimValueConversion.fromCbor(.double(18.5)) == nil)
    #expect(DcqlClaimValueConversion.fromCbor(.double(.infinity)) == nil)
    #expect(DcqlClaimValueConversion.fromCbor(.double(.nan)) == nil)
  }

  @Test func jsonPathsReadActualValuesIncludingArrayDisclosures() throws {
    let root = try JSON(data: Data(#"{"age_over_18":true,"age":18,"items":[{"value":false},{"value":"true"},{"value":18}],"unsupported":null}"#.utf8))
    #expect(DcqlClaimValueConversion.fromJson(root, at: .claim("age_over_18")) == [.boolean(true)])
    #expect(DcqlClaimValueConversion.fromJson(root, at: .claim("age")) == [.integer(18)])
    let wildcard = ClaimPath([.claim(name: "items"), .allArrayElements, .claim(name: "value")])
    #expect(DcqlClaimValueConversion.fromJson(root, at: wildcard) == [.boolean(false), .string("true"), .integer(18)])
    let indexed = ClaimPath([.claim(name: "items"), .arrayElement(index: 1), .claim(name: "value")])
    #expect(DcqlClaimValueConversion.fromJson(root, at: indexed) == [.string("true")])
    #expect(DcqlClaimValueConversion.fromJson(root, at: .claim("unsupported")).isEmpty)
    #expect(DcqlClaimValueConversion.fromJson(root, at: .claim("missing")).isEmpty)
  }
}
