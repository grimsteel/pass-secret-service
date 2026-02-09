# Pass Secret Service

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/grimsteel/pass-secret-service/release.yml?style=for-the-badge&logo=github)

Implementation of [`org.freedesktop.secrets`](https://specifications.freedesktop.org/secret-service-spec/latest/) using [`pass`](https://www.passwordstore.org/)

Secrets are stored in GPG files under `~/.password-store/secret-service`. Attributes are not encrypted.

## Installation

[![AUR Badge](https://img.shields.io/aur/version/pass-secret-service-bin?style=for-the-badge&logo=archlinux&label=AUR:%20BIN)](https://aur.archlinux.org/packages/pass-secret-service-bin)

[![AUR Badge](https://img.shields.io/aur/version/pass-secret-service-git?style=for-the-badge&logo=archlinux&label=AUR:%20GIT)](https://aur.archlinux.org/packages/pass-secret-service-git)

There are prebuilt binaries for `x86_64-unknown-linux-gnu` on the Releases page.

### Building from source

Does not require any additional dependencies to build (uses a pure-rust D-Bus implementation)

```sh
cargo build --release
```

A systemd user unit and a D-Bus session activation file are located in the `systemd` directory

## Usage

```
Usage: pass-secret-service [-d <path>] [-f] [-V] [--log-level <log-level>] [<command>] [<args>]

Background daemon for pass-secret-service: An implementation of org.freedesktop.secrets using pass

Options:
  -d, --path        location of the password store. Will fall back to
                    $PASSWORD_STORE_DIR, or $HOME/.password-store if not set.
  -f, --forget-password-on-lock
                    make gpg-agent forget the cached key password when any
                    collection is locked
  -V, --version     print the current version
  --log-level       log level (overridden by $RUST_LOG environment variable)
                    uses env_logger syntax
  --help, help      display usage information

Commands:
  run-service       Run the secret-service provider
  last-accessor     Retrieve the last application to access the specified secret
```

The subcommand is optional; ommitting it defaults to `run-service`.

### Getting the last secret accessor (#20)

The service stores information about the last accessor for each secret in memory.

Whenever a process requests a secret (not attributes/other metadata), the PID, UID, and program name are stored.

These can be retrieved with the `last-accessor` subcommand with the secret ID:

```
Usage: pass-secret-service last-accessor <id> [-C <collection>] [-A <alias>]

Retrieve the last application to access the specified secret

Positional Arguments:
  id                the secret ID. use `secret-tool search` to find

Options:
  -C, --collection  the collection of the secret. Takes precedence over --alias
  -A, --alias       the collection alias of the secret. `default` if neither
                    this nor --collection is given.
  --help, help      display usage information
```

**Example output**:
```
[INFO  pass_secret_service] The last access of collection/default/abcd123 was 15m 41s ago:
[INFO  pass_secret_service]   User: 1000
[INFO  pass_secret_service]   Program: gh (PID 123456)
[INFO  pass_secret_service]   Timestamp: Sun, 1 Jan 2026 01:23:45
```
