// CryptoKit ML-DSA (iOS 26+) for Kotlin/Native. CryptoKit has no Objective-C headers, so this file exposes the
// few operations Warden needs as @objc classes; swiftc emits the Objective-C header that cinterop consumes.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Error domain and codes understood by the Kotlin side.
@objc public enum WardenMlDsaErrorCode: Int {
  /// User authentication was cancelled or failed.
  case unlockFailed = 1
  /// The OS, device, or parameter set does not support the requested operation.
  case unsupported = 2
  /// Anything else (invalid key blob, CryptoKit failure, ...).
  case failed = 3
}

private let errorDomain = "at.asitplus.warden.mldsa"

private func wardenError(_ code: WardenMlDsaErrorCode, _ message: String, _ underlying: Error? = nil) -> NSError {
  var info: [String: Any] = [NSLocalizedDescriptionKey: message]
  if let underlying { info[NSUnderlyingErrorKey] = underlying as NSError }
  return NSError(domain: errorDomain, code: code.rawValue, userInfo: info)
}

/// LocalAuthentication and Security-framework authentication failures surface as these.
private func isAuthenticationFailure(_ error: Error) -> Bool {
  let ns = error as NSError
  if ns.domain == LAErrorDomain { return true }
  if ns.domain == NSOSStatusErrorDomain {
    return ns.code == Int(errSecUserCanceled) || ns.code == Int(errSecAuthFailed)
      || ns.code == Int(errSecInteractionNotAllowed)
  }
  if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? Error { return isAuthenticationFailure(underlying) }
  return false
}

private func mapError(_ error: Error, _ operation: String) -> NSError {
  if isAuthenticationFailure(error) {
    return wardenError(.unlockFailed, "\(operation): user authentication failed or was cancelled", error)
  }
  return wardenError(.failed, "\(operation) failed: \(error)", error)
}

@objc public class WardenMlDsaKey: NSObject {
  /// Raw FIPS 204 public key.
  @objc public let publicKey: Data
  /// Secure Enclave `dataRepresentation`, or the software key's `integrityCheckedRepresentation`.
  @objc public let keyBlob: Data
  @objc public let secureEnclave: Bool

  init(publicKey: Data, keyBlob: Data, secureEnclave: Bool) {
    self.publicKey = publicKey
    self.keyBlob = keyBlob
    self.secureEnclave = secureEnclave
  }
}

@objc public class WardenMlDsaSignature: NSObject {
  @objc public let signature: Data
  /// Raw public key of the key that produced the signature (restored from the blob).
  @objc public let publicKey: Data

  init(signature: Data, publicKey: Data) {
    self.signature = signature
    self.publicKey = publicKey
  }
}

/// Parameter sets are passed as 65 or 87 (CryptoKit has no ML-DSA-44).
@objc public class WardenMlDsa: NSObject {

  /// Whether this OS supports the parameter set, and (if `secureEnclave`) whether a Secure Enclave is available.
  @objc public class func isSupported(_ parameterSet: Int, secureEnclave: Bool) -> Bool {
    guard parameterSet == 65 || parameterSet == 87 else { return false }
    if #available(iOS 26.0, macOS 26.0, *) {
      return !secureEnclave || SecureEnclave.isAvailable
    }
    return false
  }

  /// Generates a key. `accessControl` applies to Secure Enclave keys only.
  @objc public class func generate(
    _ parameterSet: Int, accessControl: SecAccessControl?, secureEnclave: Bool
  ) throws -> WardenMlDsaKey {
    guard isSupported(parameterSet, secureEnclave: secureEnclave) else {
      throw wardenError(.unsupported, "ML-DSA-\(parameterSet) (Secure Enclave: \(secureEnclave)) is not supported here")
    }
    guard #available(iOS 26.0, macOS 26.0, *) else { throw wardenError(.unsupported, "requires iOS 26") }
    do {
      switch (parameterSet, secureEnclave) {
      case (65, true):
        let key = try accessControl.map { try SecureEnclave.MLDSA65.PrivateKey(accessControl: $0) }
          ?? SecureEnclave.MLDSA65.PrivateKey()
        return WardenMlDsaKey(publicKey: key.publicKey.rawRepresentation, keyBlob: key.dataRepresentation, secureEnclave: true)
      case (87, true):
        let key = try accessControl.map { try SecureEnclave.MLDSA87.PrivateKey(accessControl: $0) }
          ?? SecureEnclave.MLDSA87.PrivateKey()
        return WardenMlDsaKey(publicKey: key.publicKey.rawRepresentation, keyBlob: key.dataRepresentation, secureEnclave: true)
      case (65, false):
        let key = try MLDSA65.PrivateKey()
        return WardenMlDsaKey(publicKey: key.publicKey.rawRepresentation, keyBlob: key.integrityCheckedRepresentation, secureEnclave: false)
      case (87, false):
        let key = try MLDSA87.PrivateKey()
        return WardenMlDsaKey(publicKey: key.publicKey.rawRepresentation, keyBlob: key.integrityCheckedRepresentation, secureEnclave: false)
      default:
        throw wardenError(.unsupported, "ML-DSA-\(parameterSet) is not supported")
      }
    } catch let error as NSError where error.domain == errorDomain {
      throw error
    } catch {
      throw mapError(error, "ML-DSA-\(parameterSet) key generation")
    }
  }

  /// Signs `message` (pure ML-DSA, empty context) with the key restored from `keyBlob`.
  /// `context` carries user authentication for protected Secure Enclave keys.
  @objc public class func sign(
    _ parameterSet: Int, keyBlob: Data, secureEnclave: Bool, context: LAContext?, message: Data
  ) throws -> WardenMlDsaSignature {
    guard #available(iOS 26.0, macOS 26.0, *) else { throw wardenError(.unsupported, "requires iOS 26") }
    do {
      switch (parameterSet, secureEnclave) {
      case (65, true):
        let key = try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: keyBlob, authenticationContext: context)
        return WardenMlDsaSignature(signature: try key.signature(for: message), publicKey: key.publicKey.rawRepresentation)
      case (87, true):
        let key = try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: keyBlob, authenticationContext: context)
        return WardenMlDsaSignature(signature: try key.signature(for: message), publicKey: key.publicKey.rawRepresentation)
      case (65, false):
        let key = try MLDSA65.PrivateKey(integrityCheckedRepresentation: keyBlob)
        return WardenMlDsaSignature(signature: try key.signature(for: message), publicKey: key.publicKey.rawRepresentation)
      case (87, false):
        let key = try MLDSA87.PrivateKey(integrityCheckedRepresentation: keyBlob)
        return WardenMlDsaSignature(signature: try key.signature(for: message), publicKey: key.publicKey.rawRepresentation)
      default:
        throw wardenError(.unsupported, "ML-DSA-\(parameterSet) is not supported")
      }
    } catch let error as NSError where error.domain == errorDomain {
      throw error
    } catch {
      throw mapError(error, "ML-DSA-\(parameterSet) signing")
    }
  }

  /// Verifies a signature with CryptoKit (used by tests to cross-check against BouncyCastle).
  @objc public class func verify(_ parameterSet: Int, publicKey: Data, message: Data, signature: Data) -> Bool {
    guard #available(iOS 26.0, macOS 26.0, *) else { return false }
    switch parameterSet {
    case 65: return (try? MLDSA65.PublicKey(rawRepresentation: publicKey))?.isValidSignature(signature, for: message) ?? false
    case 87: return (try? MLDSA87.PublicKey(rawRepresentation: publicKey))?.isValidSignature(signature, for: message) ?? false
    default: return false
    }
  }
}
