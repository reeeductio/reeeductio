# Swift SDK Design Notes

## Overview

A native Swift SDK for iOS and tvOS, targeting SwiftUI apps built on the reeeductio Spaces API.

---

## Repository Structure

**Decision: separate repo**, not the monorepo.

Reasons:
- Swift Package Manager is git-URL-based; iOS devs add dependencies via `https://github.com/org/reeeductio-swift`, not by cloning a monorepo
- Swift CI requires macOS runners with Xcode; incompatible with the existing Linux-centric backend/Python/TS pipeline
- Keeps Xcode toolchain noise out of the monorepo
- Clean version tags (v1.0.0) and small clone footprint for consumers

The canonical [openapi.yaml](../openapi.yaml) stays in the monorepo as the source of truth.

**Repo name:** `reeeductio-swift`

---

## Repo Layout

```
reeeductio-swift/
  Package.swift
  Sources/
    Reeeductio/          # Swift client SDK
      Models/            # Message, Member, Role, Capability structs
      Client/            # Space, Topic observable classes
      Crypto/            # CryptoKit wrappers for Ed25519 + AES-GCM
      Network/           # URLSession + WebSocket internals
      Auth/              # Challenge-response + OPAQUE flows
    OpaqueSwift/         # Generated UniFFI Swift wrappers (from opaque-swift build)
  Tests/
    ReeeductioTests/
```

---

## Platform Targets

- **iOS 17+** (uses `@Observable` macro)
- **tvOS 17+**
- iOS 16 / tvOS 16 support possible later via `ObservableObject` fallback

---

## Data Model Design

### Principle: transform at the boundary

The wire format uses base64 strings, millisecond-epoch integers, and raw bytes. None of that crosses into Swift model types — conversion happens at decode time.

### Typed IDs

Prevents mixing a `spaceId` with a `userId` at compile time:

```swift
struct SpaceID:   RawRepresentable, Hashable, Codable { let rawValue: String }
struct UserID:    RawRepresentable, Hashable, Codable { let rawValue: String }
struct MessageID: RawRepresentable, Hashable, Codable { let rawValue: String }
struct BlobID:    RawRepresentable, Hashable, Codable { let rawValue: String }
```

### Core model types

```swift
// Identifiable so List/ForEach work without specifying id:
struct Message: Identifiable, Hashable {
    var id: MessageID { messageHash }
    let messageHash: MessageID
    let topicId: String
    let type: String
    let prevHash: MessageID?
    let encryptedData: Data     // decoded from base64 at boundary
    let sender: UserID
    let serverTimestamp: Date   // converted from Int64 ms at boundary
}

// Decrypted variant — apps work with this, not Message directly
struct DecryptedMessage: Identifiable {
    var id: MessageID { raw.messageHash }
    let raw: Message
    let plaintext: Data
}
```

### Observable classes

```swift
@Observable
final class Space {
    let spaceId: SpaceID
    private(set) var isAuthenticated = false
    private(set) var currentUserID: UserID?

    func authenticate() async throws
    func topic(_ id: String) -> Topic   // returns same instance if called again
}

@Observable
final class Topic {
    let topicId: String
    private(set) var messages: [DecryptedMessage] = []
    private(set) var isLoading = false
    private(set) var hasMore = false

    func loadHistory(limit: Int = 50) async throws
    func post(type: String, plaintext: Data) async throws

    // WebSocket updates as AsyncSequence — works directly with .task modifier
    var liveUpdates: AsyncStream<DecryptedMessage> { get }
}
```

Typical SwiftUI usage:

```swift
List(topic.messages) { msg in
    MessageRow(message: msg)
}
.task {
    try? await topic.loadHistory()
    for await msg in topic.liveUpdates {
        // @Observable handles the UI refresh automatically
    }
}
```

### Timestamp and binary data rules

| Wire format | Swift model type |
|---|---|
| `Int64` milliseconds | `Date` |
| base64 `String` | `Data` |
| bare `String` ID | typed `RawRepresentable` wrapper |

---

## Cryptography

Use **CryptoKit** throughout — built-in, covers all required primitives:

| Primitive | CryptoKit API |
|---|---|
| Ed25519 signing | `Curve25519.Signing` |
| AES-GCM encryption | `AES.GCM` |
| HKDF key derivation | `HKDF` |
| SHA-512 | `SHA512` |

No external crypto libraries needed for the main SDK.

---

## Networking

- **URLSession async/await** for HTTP — no Alamofire
- **URLSessionWebSocketTask** for real-time streams, wrapped in `AsyncStream`

---

## OPAQUE Integration

### Background

OPAQUE is used for password-based key recovery only (not authentication). The backend uses `opaque-ke` (Rust, via `opaque-snake` PyO3 bindings). The TypeScript SDK uses `@serenity-kit/opaque` (WASM build of `opaque-ke`).

For Swift, cipher suite compatibility is required:
- **OPRF:** Ristretto255
- **KE:** TripleDH with Ristretto255 + SHA-512
- **KSF:** Argon2
- **opaque-ke version:** 4.1.0-pre.1

`GeorgeLyon/Opaque` (pure Swift, secp256r1 + SHA-3) and `libopaque` (C, potentially different internal parameters) are **not compatible** with the backend cipher suite.

### Decision: new `opaque-swift` repo (UniFFI)

A new standalone Rust crate — `opaque-swift` — that wraps `opaque-ke` with UniFFI Swift bindings. Parallel to `opaque-snake`, same cipher suite, client-side only (`OpaqueClient`; no server needed in Swift).

**Why UniFFI over alternatives:**
- Guaranteed byte-level cipher suite compatibility (same Rust crate as the backend)
- UniFFI is production-proven (Mozilla Firefox iOS/Android uses it)
- Generates idiomatic Swift `async throws` APIs, not raw C pointers
- No C++ bridge needed (unlike `serenity-kit/react-native-opaque`'s `cxx` approach)

### `opaque-swift` repo layout

```
opaque-swift/
  Cargo.toml               # staticlib, opaque-ke + uniffi deps
  src/
    lib.rs                 # uniffi::setup_scaffolding!()
    cipher_suite.rs        # DefaultCipherSuite (identical to opaque-snake)
    client.rs              # #[uniffi::export] OpaqueClient
    messages.rs            # StartRegistrationResult, FinishRegistrationResult, etc.
    errors.rs              # OpaqueError with #[uniffi::Error]
  scripts/
    build-xcframework.sh   # cross-compile + lipo + xcodebuild
  Package.swift            # SPM binary package
  Sources/OpaqueSwift/     # Generated UniFFI .swift wrapper (committed)
  .github/workflows/
    release.yml            # macOS CI: build + upload XCFramework to release
```

### Swift API surface

```swift
public class OpaqueClient {
    public init()

    // Registration
    public func startRegistration(password: String) throws -> StartRegistrationResult
    public func finishRegistration(password: String, state: Data, response: Data)
        throws -> FinishRegistrationResult

    // Login
    public func startLogin(password: String) throws -> StartLoginResult
    public func finishLogin(password: String, state: Data, response: Data)
        throws -> FinishLoginResult
}

public struct StartRegistrationResult {
    public let request: Data    // send to server
    public let state: Data      // keep for finishRegistration
}

public struct FinishRegistrationResult {
    public let upload: Data     // send to server
    public let exportKey: Data  // 64 bytes — derive credential-wrapping key from this
}

public struct StartLoginResult {
    public let request: Data
    public let state: Data
}

public struct FinishLoginResult {
    public let finalization: Data
    public let exportKey: Data   // 64 bytes — used to decrypt stored credentials
    public let sessionKey: Data
}
```

The `state` fields serialize/deserialize `opaque-ke`'s internal stateful types to `Data` at each step boundary, keeping the FFI surface simple.

### Build process

```bash
# Cross-compile for iOS targets
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim
cargo build --release --target x86_64-apple-ios

# Combine simulator slices (required before xcodebuild)
lipo -create \
  target/aarch64-apple-ios-sim/release/libopaque_swift.a \
  target/x86_64-apple-ios/release/libopaque_swift.a \
  -output target/universal-sim/libopaque_swift.a

# Generate Swift wrapper
uniffi-bindgen-swift generate \
  target/aarch64-apple-ios/release/libopaque_swift.a \
  --out-dir Sources/OpaqueSwift
mv Sources/OpaqueSwift/opaque_swiftFFI.modulemap \
   Sources/OpaqueSwift/module.modulemap

# Package as XCFramework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libopaque_swift.a \
  -headers Sources/OpaqueSwift \
  -library target/universal-sim/libopaque_swift.a \
  -headers Sources/OpaqueSwift \
  -output OpaqueSwift.xcframework
```

### Package.swift structure

```swift
let package = Package(
    name: "OpaqueSwift",
    platforms: [.iOS(.v16), .tvOS(.v16)],
    products: [.library(name: "OpaqueSwift", targets: ["OpaqueSwift"])],
    targets: [
        .binaryTarget(
            name: "OpaqueSwiftFFI",
            url: "https://github.com/cvwright/opaque-swift/releases/download/v0.1.0/OpaqueSwift.xcframework.zip",
            checksum: "<computed>"
        ),
        .target(
            name: "OpaqueSwift",
            dependencies: ["OpaqueSwiftFFI"],
            path: "Sources/OpaqueSwift"
        ),
        .testTarget(name: "OpaqueSwiftTests", dependencies: ["OpaqueSwift"]),
    ]
)
```

### Verification

1. `cargo build --target aarch64-apple-ios` succeeds (no iOS-incompatible deps)
2. `bash scripts/build-xcframework.sh` produces `OpaqueSwift.xcframework.zip`
3. Swift integration test: full registration → login round trip against a local reeeductio server
4. **Interop check:** run the same registration with `opaque_snake` (Python) on the server side and `OpaqueClient` (Swift) on the client side — verify `export_key` bytes match
5. `lipo -info` on simulator fat binary shows both `arm64` slices

---

## Summary of Key Decisions

| Decision | Choice | Reason |
|---|---|---|
| Repo | Separate `reeeductio-swift` | SPM git-URL distribution, clean CI |
| Distribution | Swift Package Manager | Standard for iOS |
| iOS target | 17+ (`@Observable`) | Modern SwiftUI |
| Observable pattern | `@Observable` macro | Simpler than `ObservableObject` |
| Timestamps | `Date` (converted at decode) | SwiftUI-friendly |
| Binary data | `Data`, never base64 `String` | Clean models |
| IDs | Typed `RawRepresentable` wrappers | Compile-time safety |
| Crypto | CryptoKit only | Built-in, no dependencies |
| Networking | URLSession only | Built-in, no Alamofire |
| WebSocket | `AsyncStream<DecryptedMessage>` | Works with `.task {}` modifier |
| OPAQUE backend | `opaque-ke` via UniFFI (new `opaque-swift` repo) | Cipher suite compatibility |
| OPAQUE approach | UniFFI proc-macros (`#[uniffi::export]`) | Modern, no UDL file needed |
| OPAQUE scope | Client-side only | Server stays Python |
