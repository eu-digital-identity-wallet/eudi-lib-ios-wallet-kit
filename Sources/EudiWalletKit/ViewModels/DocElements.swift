/*
Copyright (c) 2023 European Commission

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
import MdocDataModel18013
import MdocDataTransfer18013

public struct DocPresentInfo {
	let docType: String
	let docDataFormat: DocDataFormat
	let displayName: String?
	let typedData: DocTypedData
}

public enum DocElements {
	case msoMdoc(MsoMdocElements)
	case sdJwt(SdJwtElements)
}

/// MdocElements
public struct MsoMdocElements: Identifiable, Sendable {
	public var id: String { docId }
	public var docId: String
	public let docType: String
	public let displayName: String?
	public var nameSpacedElements: [NameSpacedElements]
}

public struct SdJwtElements: Identifiable, Sendable {
	public var id: String { docId }
	public var docId: String
	public let vct: String
	public let displayName: String?
	public var isEnabled: Bool
	public var sdJwtElements: [SdJwtElement]
}

extension IssuerSigned {
	func extractMsoMdocElements(docId: String, docType: String, displayName: String?, itemsRequested: [NameSpace: [RequestItem]]) -> MsoMdocElements {
		MsoMdocElements(docId: docId, docType: docType, displayName: displayName, nameSpacedElements: itemsRequested.compactMap { ns, requestItems in
			extractNameSpacedElements(docType: docType, ns: ns, requestItems: requestItems)
		})
	}

	func extractNameSpacedElements(docType: String, ns: String, requestItems: [RequestItem]) -> NameSpacedElements? {
		guard let issuedItems = issuerNameSpaces?[ns] else { return nil }
		let mandatoryElementKeys = MsoMdocElements.getMandatoryElementKeys(docType: docType, ns: ns)
		return NameSpacedElements(nameSpace: ns, elements: requestItems.map { $0.extractMsoMdocElement(nsItems: issuedItems, isMandatory: mandatoryElementKeys.contains($0.rootIdentifier)) })
	}
}

extension RequestItem {
	func extractMsoMdocElement(nsItems: [IssuerSignedItem], isMandatory: Bool) -> MsoMdocElement {
		let issuedElement = nsItems.first { $0.elementIdentifier == rootIdentifier }
		let stringValue = issuedElement?.description
		return MsoMdocElement(elementIdentifier: elementIdentifier, displayName: rootDisplayName, isOptional: !isMandatory, intentToRetain: intentToRetain ?? false, stringValue: stringValue, isValid: issuedElement != nil)
	}
}

extension MsoMdocElements {

	static func getMandatoryElementKeys(docType: String, ns: String) -> [String] {
		switch (docType, ns) {
		case (IsoMdlModel.isoDocType, IsoMdlModel.isoNamespace):
			return IsoMdlModel.isoMandatoryElementKeys
		case (EuPidModel.euPidDocType, "eu.europa.ec.eudi.pid.1"):
			return EuPidModel.pidMandatoryElementKeys
		default:
			return []
		}
	}
}
/*
extension RequestItems {
	func toDocElementViewModels(docId: String, docType: String, displayName: String?, valid: Bool) -> [DocElements] {
		compactMap { dType, nsItems in
			if !Openid4VpUtils.vctToDocTypeMatch(dType, docType) {
				nil
			}
			else {
				DocElementsViewModel(docId: docId, docType: docType, displayName: displayName, isEnabled: valid, elements: DocElementsViewModel.fluttenItemViewModels(nsItems, valid: valid, mandatoryElementKeys: DocElementsViewModel.getMandatoryElementKeys(docType: docType)))
			}
		}
	}
}
*/

public struct NameSpacedElements: Identifiable, Sendable {
	public var id: String { nameSpace }
	public let nameSpace: String
	public var elements: [MsoMdocElement]
}

public struct MsoMdocElement: Identifiable, Sendable {
	public var id: String { elementIdentifier }
	/// path to locate the element
	public let elementIdentifier: String
	// display names of the component paths
	public let displayName: String?
	public let isOptional: Bool
	public let intentToRetain: Bool
	public let stringValue: String?
	public var isValid: Bool
	public var isSelected = true
}

public struct SdJwtElement: Identifiable, Sendable {
	public var id: String { elementPath.joined(separator: ".") }
	/// path to locate the element
	public let elementPath: [String]
	// display names of the component paths
	public let displayNames: [String?]
	public let isOptional: Bool
	public let intentToRetain: Bool
	public var isEnabled: Bool
	public var isSelected = true
}


