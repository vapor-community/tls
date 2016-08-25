# Transport Layer Security (TLS/SSL) for Swift

> Transport Layer Security (TLS) is the successor to Secure Socket Layer 3.0 (SSL). SSL 3.0 was deprecated in June 2015.
> https://tools.ietf.org/html/rfc7568

![Swift](http://img.shields.io/badge/swift-v3.0--dev.08.18-brightgreen.svg)
[![Build Status](https://travis-ci.org/vapor/tls.svg?branch=master)](https://travis-ci.org/vapor/tls)
[![CircleCI](https://circleci.com/gh/vapor/tls.svg?style=shield)](https://circleci.com/gh/vapor/tls)
[![Slack Status](http://vapor.team/badge.svg)](http://vapor.team)

A Swift wrapper for Transport Layer Security (TLS/SSL) using OpenSSL.

- [x] Swifty Interface
- [x] Client and Server
- [x] Tested

## Examples

The examples below assume you already have a socket library and you want to add TLS. If you do not already have a socket library, check out [Socks](https://github.com/czechboy0/Socks) by Honza Dvorsky. 

There is an add-on for Socks called [SecretSocks](https://github.com/czechboy0/SecretSocks) that includes this TLS library and provides a convenient `makeSecret()` method for all Socks' sockets.

If you are using a different socket library, no need to worry. You only need access to the socket's file descriptor to use this package.

```swift
import TLS

let socket: MyUnsecureSocket

// Create an unsecure socket
// and grab its file descriptor.
// ...

let descriptor: Int32 = socket.mySocketDescriptor
```

Now that you have the descriptor, let's add TLS.

### Client

This adds a Transport Security Layer for interacting with a server from a client. No certificates are required to be a client.

```swift
let context = try TLS.Context(mode: .client, certificates: .none)
let secureSocket = try TLS.Socket(context: context, descriptor: descriptor)

try secureSocket.connect()
```

Here a context is created. You should hold on to this context if you intend to create multiple sockets. Your socket `descriptor` is then used with the `context` to create an `TLS.Socket`. 

The call to `connect()` creates the connection to the server to start sending and receiving data. This should be called **after** the unsecure socket has called its version of `connect()`.

### Server 

This adds a Transport Security Layer for interacting with a client from a server. Setting up a server requires certificates.

```swift
let context = try TLS.Context(mode: .server, certificates: .files(
    certificateFile: "./Certs/cert.pem",
    privateKeyFile: "./Certs/key.pem",
    signature: .selfSigned
))

let secureSocket = try TLS.Socket(context: context, descriptor: descriptor)

try secureSocket.accept()
```

Here a context is created. You should hold on to this context if you intend to create multiple sockets. Your socket `descriptor` is then used with the `context` to create an `TLS.Socket`. 

The call to `accept()` accepts the connection and performs the TLS handshake with the client. This should be called **after** the unsecure socket has called its version of `accept()`.

### Sending / Receiving

You can now send and receive data through the new secure socket.

```swift
try secureSocket.send([0x00, 0x01, 0x02])
let data = try secureSocket.receive(max: 3)
```

### Certificates

The `Certificates` enum lets you supply the appropriate certificates for your TLS-enabled server.

```swift
public enum Certificates {
    case none
    case files(certificateFile: String, privateKeyFile: String, signature: Certificate.Signature)
    case chain(chainFile: String, signature: Certificate.Signature)
}

public enum Certificate.Signature {
    case selfSigned
    case signedFile(caCertificateFile: String)
    case signedDirectory(caCertificateDirectory: String)
}
```

### Verification

You can verify the certificates presented by the peer manually.

```swift
try socket.verifyConnection()
```

### Errors

The `Error` enum comprises all errors that can be thrown from this module. The `String` in all of the cases is a readable error message from OpenSSL.

```swift
public enum Error: ErrorProtocol {
    case methodCreation
    case contextCreation
    case loadCACertificate(String)
    case useCertificate(String)
    case usePrivateKey(String)
    case checkPrivateKey(String)
    case useChain(String)
    case socketCreation(String)
    case file(String)
    case accept(SocketError, String)
    case connect(SocketError, String)
    case send(SocketError, String)
    case receive(SocketError, String)
    case invalidPeerCertificate(PeerCertificateError)
}
```

Some cases of the `Error` enum contain `SocketError`s inside.

```swift
public enum SocketError: Int32, ErrorProtocol {
    case none
    case zeroReturn
    case wantRead
    case wantWrite
    case wantConnect
    case wantAccept
    case wantX509Lookup
    case syscall
    case ssl
    case unknown
}
```

One case of the `Error` enum contains `PeerCertificateError`s inside. This is thrown by `verifyConnection()`.

```swift
public enum PeerCertificateError {
    case notPresented
    case noIssuerCertificate
    case invalid
}
```

## Using with Xcode

Swift Package Manager will automatically build this project correctly, but when using with Xcode, you will need to add a setting to your Xcode project file:

Under Project > Build Settings > Library Search Paths, add:

```
$(PROJECT_DIR)/**
```

## Vapor

This wrapper was created to power [Vapor](https://github.com/qutheory/vapor), an Web Framework for Swift. 

## Author

Created by [Tanner Nelson](https://github.com/tannernelson).
