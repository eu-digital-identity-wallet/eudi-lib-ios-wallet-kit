//
//  DisclosedDocumentSet.swift
//  EudiWalletKit
//
//  Created by PHILIP SAKELLAROPOULOS on 7/30/26.
//
import Foundation

/// A set of documents that can be disclosed in response to a single presentation request.
///
/// When a verifier request is decoded, the wallet builds one instance per request,
/// containing the matching stored documents with the elements the user can select to disclose,
/// together with any policy warnings raised while validating the request against the
/// relying party's registration policy.
///
/// Instances are published by ``PresentationSession/disclosedDocumentSets`` for the UI
/// to present the selectable items to the user.
public struct DisclosedDocumentSet {
	/// The requested elements of each matching document, grouped per document and format (mso-mdoc or SD-JWT).
	public let docElements: [DocElements]
	/// Violations of the relying party's registration policy detected for this request.
	/// The presentation can still proceed; these are surfaced to the user as warnings.
	public let warnings: [PresentationPolicyViolation]?

	/// Creates a disclosed document set.
	/// - Parameters:
	///   - docElements: The requested elements of each matching document.
	///   - warnings: Registration-policy violations to surface to the user.
	public init(docElements: [DocElements], warnings: [PresentationPolicyViolation]?) {
		self.docElements = docElements
		self.warnings = warnings
	}
}
 
