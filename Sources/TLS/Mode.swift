/**
    Secure sockets can be created as either Clients or Servers.
    Server sockets call `accept()` while Client sockets call `connect()`.
*/
public enum Mode {
    case client, server
}
