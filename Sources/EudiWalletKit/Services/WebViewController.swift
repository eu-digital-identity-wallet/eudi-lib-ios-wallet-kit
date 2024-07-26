//
// OAuth2
// Copyright (C) 2015 Leon Breedt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#if os(iOS)
import UIKit
/// Type of view controllers for the OS. (`UIViewController` on iOS).
public typealias ControllerType = UIViewController
#elseif os(OSX)
import Cocoa
/// Type of view controllers for the OS. (`NSViewController` on OSX).
public typealias ControllerType = NSViewController
#endif
import WebKit

var titleObservation = 1

/// Enumerates the possible responses for a web view based request.
public enum WebViewResponse {
		/// A general error occurred while attempting to load the request.
		/// - Parameters:
		///   - error: The error that occurred while loading.
		case loadError(error: Error)

		/// An error occurred while attempting to load the request, and the
		/// HTTP response is available for further consultation.
		/// - Parameters:
		///   - response: The HTTP response that can be consulted to attempt to determine the root cause.
	case responseError(response: HTTPURLResponse)

		/// Completed, and a redirect was performed.
		/// - Parameters:
		///   - redirectionURL: The full URL (with any query parameters) that the server redirected to.
		case redirection(redirectionURL: URL)
}

/// A completion handler for web view requests.
public typealias WebViewCompletionHandler = (WebViewResponse) -> Void

/// Represents a view controller that can be used to execute URL requests.
public protocol WebViewControllerType {
		/// Presents the controller and triggers the URL request.
		func present()
		/// Dismisses the controller.
		func dismiss()

		/// Gets or sets the web view configuration to use, if applicable.
		var webViewConfiguration: WKWebViewConfiguration? { get set }
}

/// Controller for displaying a web view, performing an `NSURLRequest` inside it,
/// and intercepting redirects to a well-known URL.
public class WebViewController: ControllerType, WKNavigationDelegate, WebViewControllerType {
		/// The `WKWebView` which will be used for requests.
		public private(set) weak var webView: WKWebView!

		/// Gets or sets the configuration for the `WKWebView` for this controller. After the
		/// `WKWebView` has been instantiated, always returns the configuration of web view.
		/// Setting is ignored after the `WKWebView` has been instantiated.
		public var webViewConfiguration: WKWebViewConfiguration? {
				get { return webView?.configuration ?? defaultWebViewConfiguration }
				set {
						if webView == nil {
								defaultWebViewConfiguration = newValue
						}
				}
		}

		private var defaultWebViewConfiguration: WKWebViewConfiguration?

		let request: URLRequest!
		let redirectionURL: URL!
		let completionHandler: WebViewCompletionHandler!

#if os(iOS)
		/// Creates a new `WebViewController` for an `NSURLRequest` and a given redirection URL.
		/// - Parameters:
		///   - request: The URL request that will be loaded when `loadRequest` is called.
		///   - redirectionURL: The redirection URL which will trigger a completion if the
		///                     server attempts to redirect to it.
		///   - completionHandler: The handler to call when the request completes (successfully or otherwise).
		public required init(request: URLRequest,
												 redirectionURL: URL,
												 completionHandler: @escaping WebViewCompletionHandler) {
				self.request = request
				self.redirectionURL = redirectionURL
				self.completionHandler = completionHandler
				super.init(nibName: nil, bundle: nil)
		}
#elseif os(OSX)
		/// Creates a new `WebViewController` for an `NSURLRequest` and a given redirection URL.
		/// - Parameters:
		///   - request: The URL request that will be loaded when `loadRequest` is called.
		///   - redirectionURL: The redirection URL which will trigger a completion if the
		///                     server attempts to redirect to it.
		///   - completionHandler: The handler to call when the request completes (successfully or otherwise).
		public init?(request: NSURLRequest,
								 redirectionURL: NSURL,
								 completionHandler: WebViewCompletionHandler) {
				self.request = request
				self.redirectionURL = redirectionURL
				self.completionHandler = completionHandler
				super.init(nibName: nil, bundle: nil)
		}
#endif

		/// Not supported for `WebViewController`.
		/// - Parameter coder: The `NSCoder`.
		public required init?(coder aDecoder: NSCoder) {
				fatalError("init(coder:) is not supported for WebViewController")
		}

		/// Loads the web view's `NSURLRequest`, invoking `completionHandler` when a redirection attempt
		/// to the `redirectionURL` is made.
		public func present() {
			DispatchQueue.main.async {
				if #available(iOS 15.0, *) {
#if os(iOS)
					let navigationController = UINavigationController(rootViewController: self)
					if let window = UIApplication.shared.firstKeyWindow,
						 let rootViewController = window.rootViewController {
						rootViewController.present(navigationController,
																			 animated: true,
																			 completion: nil)
					} else {
						fatalError("unable to find root view controller")
					}
					self.loadViewIfNeeded()
#elseif os(OSX)
					fatalError("OS X support not implemented yet for web view controllers")
#endif
				} else {
					fatalError("unable to find root view controller")
				}
				self.webView.load(self.request as URLRequest)
				}
		}

		/// Dismisses the view controller.
		public func dismiss() {
			DispatchQueue.main.async  {
						#if os(iOS)
				self.dismiss(animated: true, completion: nil)
						#elseif os(OSX)
						fatalError("OS X support not implemented yet for web view controllers")
						#endif
				}
		}

		// MARK: - UIViewController

		public override func loadView() {
				super.loadView()

#if os(iOS)
			navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .cancel,
																														target: self,
																														action: #selector(dismissAndCancel))
#endif

				let configuration = defaultWebViewConfiguration ?? WKWebViewConfiguration()
				let webView = WKWebView(frame: CGRect.zero, configuration: configuration)
				webView.navigationDelegate = self
				webView.translatesAutoresizingMaskIntoConstraints = false
			// webView.addObserver(self, forKeyPath: "title", options: .new, context: &titleObservation)
				view.addSubview(webView)
				let heightConstraint = NSLayoutConstraint(item: webView,
																									attribute: .height,
																									relatedBy: .equal,
																									toItem: view,
																									attribute: .height,
																									multiplier: 1,
																									constant: 0)
				let widthConstraint = NSLayoutConstraint(item: webView,
																								 attribute: .width,
																								 relatedBy: .equal,
																								 toItem: view,
																								 attribute: .width,
																								 multiplier: 1,
																								 constant: 0)
				view.addConstraints([heightConstraint, widthConstraint])
				self.webView = webView
		}

		deinit {
				if let webView = webView {
						webView.removeObserver(self, forKeyPath: "title")
				}
		}
/*
		public override func observeValueForKeyPath(keyPath: String?,
																								ofObject object: AnyObject?,
																								change: [String : AnyObject]?,
																								context: UnsafeMutablePointer<Void>) {
				if context == &titleObservation {
					if let newTitle = change?[NSKeyValueChangeKey.newKey.rawValue] as? String {
								title = newTitle
						}
				}
		}
 */

		// MARK: - WKNavigationDelegate

	public func webView(_ webView: WKWebView,
											decidePolicyFor navigationAction: WKNavigationAction,
												decisionHandler: (WKNavigationActionPolicy) -> Void) {
			if isRedirectionAttempt(targetURL: navigationAction.request.url) {
						completionHandler(.redirection(redirectionURL: navigationAction.request.url!))
				decisionHandler(.cancel)
						return
				} else {
					decisionHandler(.allow)
				}
		}

	public func webView(_ webView: WKWebView,
											decidePolicyFor navigationResponse: WKNavigationResponse,
												decisionHandler: (WKNavigationResponsePolicy) -> Void) {
			if let response = navigationResponse.response as? HTTPURLResponse, response.statusCode != 200 {
						// Probably, something is bad with the request, server did not like it.
						// Forward the details on so someone else can do something meaningful with it.
						completionHandler(.responseError(response: response))
				decisionHandler(.cancel)
						return
				}
			decisionHandler(.allow)
		}

		public func webView(webView: WKWebView,
												didFail navigation: WKNavigation!,
												withError error: NSError) {
				completionHandler(.loadError(error: error))
		}

		// MARK: - Actions

	@objc public func dismissAndCancel() {
				dismiss()
		let error = NSError(domain: "WebView", code: 0, userInfo: [NSLocalizedDescriptionKey:"User canceled authentication"])
				completionHandler(.loadError(error: error))
		}

		// MARK: - Private

		func isRedirectionAttempt(targetURL: URL?) -> Bool {
				guard let targetURL else { return false }
				guard let redirectionURL else { return false }
			print(targetURL.absoluteString)
			let targetURLString = targetURL.absoluteString.lowercased()
			let redirectionURLString = redirectionURL.absoluteString.lowercased()
				return targetURLString.hasPrefix(redirectionURLString)
		}
}

extension UIApplication {
	@available(iOS 15.0, *)
	var firstKeyWindow: UIWindow? {
				return UIApplication.shared.connectedScenes
						.compactMap { $0 as? UIWindowScene }
						.filter { $0.activationState == .foregroundActive }
						.first?.keyWindow
		}
}
