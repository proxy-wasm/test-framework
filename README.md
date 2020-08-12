# WebAssembly for Proxies (test framework)

The Proxy-Wasm ABI and associated SDKs enable developers to build extensions in
any of the supported languages and deliver the plugins as WebAssembly modules at
run-time. This repository contains a standalone runner which serves as a test
harness and simulator for Proxy-Wasm extensions, enabling quick testing in a
controlled environment.

### Examples

The basic usage of this test-framework is provided in the examples/ folder which
contains mocking of proxy-wasm modules provided in the proxy-wasm-rust-sdk
examples/.

## Supported

- Low-level expectation setting over most host-side functions that are consumed
  immediately
- Checking of residual low-level expectations after wasm-function call has
  completed
- Various high-level (simulator defaults) expectations that persist across
  several host-function calls as opposed to being immediately consumed
- Expectation setting over returns from functions exposed on the proxy-wasm
  module

## In Progress

- Complete default implementation for all host-side functions
- Low-level expectation setting for the remaining host-side functions
- High-level expectation setting for the remaining host-side functions
- Integration test examples
