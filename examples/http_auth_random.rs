// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::Result;
use proxy_wasm_abi_test_harness::{tester, types::*};

fn main() -> Result<()> {
    let http_auth_random = "/usr/local/google/home/chrisagia/ws/proxy-wasm-rust-sdk/target\
                            /wasm32-unknown-unknown/release/examples/http_auth_random.wasm";
    let mut http_auth_random = tester::test(http_auth_random)?;

    http_auth_random.call_start().execute_and_expect(None)?;

    http_auth_random
        .call_proxy_on_context_create(1, 0)
        .execute_and_expect(None)?;

    http_auth_random
        .call_proxy_on_context_create(2, 1)
        .execute_and_expect(None)?;

    let http_call_headers = vec![
        (":method", "GET"),
        (":path", "/bytes/1"),
        (":authority", "httpbin.org"),
    ];
    http_auth_random
        .call_proxy_on_request_headers(2, 0)
        .expect_http_call("httpbin", http_call_headers, None, vec![], 5 * 10u64.pow(3))
        .returning(0)
        .execute_and_expect(Some(1))?;

    let buffer_data = "custom_developer_body";
    let buffer_size = buffer_data.len() as i32;
    http_auth_random
        .call_proxy_on_http_call_response(2, 0, 0, buffer_size, 0)
        .expect_get_buffer_bytes(BufferType::HttpCallResponseBody)
        .returning(buffer_data)
        .expect_send_local_response(
            403,
            Some("Access forbidden.\n"),
            vec![("Powered-By", "proxy-wasm")],
            -1,
        )
        .execute_and_expect(None)?;

    http_auth_random
        .call_proxy_on_response_headers(2, 0)
        .expect_replace_header_map_value(MapType::HttpResponseHeaders, "Powered-By", "proxy-wasm")
        .execute_and_expect(Some(0))?;

    return Ok(());
}
