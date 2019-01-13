# certificate_carver
## Overview
`certificate_carver` is a binary that searches files for X.509 certificates and uploads them to Certificate Transparency logs. It can carve files to find certificates in PEM or DER format, and it can decompress ZIP files to scan their contents. Each certificate is checked against https://crt.sh/, to determine if it has been logged before. Each new certificate that chains to a trusted root is submitted to CT log servers.

## Installation
To download a pre-compiled binary, go to the [latest release](https://github.com/divergentdave/certificate_carver/releases) and select the file corresponding to your operating system.

To build from source, clone this repository, install a rust toolchain using [rustup](https://www.rustup.rs/), and then run `cargo build`.

## Usage
Pass the directory to be scanned as a command line argument. To scan multiple directories in one invocation, pass each as a separate command line argument.

Examples:

```
./certificate_carver /path/to/directory
```

```
cargo run /path/to/directory
```
