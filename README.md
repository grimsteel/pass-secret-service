# Pass Secret Service

Implementation of [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest) using [`pass`](https://www.passwordstore.org/)

Secrets are stored in GPG files under `~/.password-store/secret-service`. Attributes are not encrypted.

## Installation

### Building from source

Does not require any additional dependencies to build (uses a pure-rust D-Bus implementation)

```sh
cargo build --release
```
