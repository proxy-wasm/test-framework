# WebAssembly for Proxies (test framework)
The Proxy-Wasm ABI and associated SDKs enable developers to build extensions in any of the supported languages and deliver the plugins as WebAssembly modules at run-time. This repository contains a standalone runner which serves as a test harness and simulator for Proxy-Wasm extensions, enabling quick testing in a controlled environment.

## TODO
- [x] Create low-level expectations set over host-functions and consumed immediately
- [ ] Implement checking of residual expectations to ensure all low-level expectations have been consumed at end of call
- [ ] Create high-level expectations that persist across several host-function calls (not immediately consumed)
- [ ] Implement generic pub fn returning(...) function to make expectation setting / mocking more intuitive
- [ ] Support expectation setting over returns from functions exposed on the proxy-wasm module
- [ ] Complete default implementation for all host-functions
