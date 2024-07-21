# Pass Secret Service

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/grimsteel/pass-secret-service/release.yml?style=for-the-badge&logo=github)

Implementation of [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service/latest) using [`pass`](https://www.passwordstore.org/)

Secrets are stored in GPG files under `~/.password-store/secret-service`. Attributes are not encrypted.

## Installation

[![AUR Badge](https://img.shields.io/aur/version/pass-secret-service-bin?style=for-the-badge&logo=archlinux)](https://aur.archlinux.org/packages/pass-secret-service-bin)

There are prebuilt binaries for `x86_64-unknown-linux-gnu` on the Releases page.

### Building from source

Does not require any additional dependencies to build (uses a pure-rust D-Bus implementation)

```sh
cargo build --release
```

A systemd user unit and a D-Bus session activation file are located in the `systemd` directory
