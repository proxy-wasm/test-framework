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
use proxy_wasm_test_framework::tester;
use proxy_wasm_test_framework::types::*;
use structopt::StructOpt;

fn main() -> Result<()> {
    let args = tester::MockSettings::from_args();
    let mut http_headers_test = tester::mock(args)?;

    http_headers_test
        .http_request(
            Some((
                MapType::HttpRequestHeaders,
                vec![
                    (":method", "GET"),
                    (":path", "/hello"),
                    (":authority", "developer"),
                ],
            )),
            None,
            None,
        )?
        .expect_log(Some(LogLevel::Trace), Some("#2 -> :method: GET"))
        .expect_log(Some(LogLevel::Trace), Some("#2 -> :path: /hello"))
        .expect_log(Some(LogLevel::Trace), Some("#2 -> :authority: developer"))
        .expect_send_local_response(
            Some(200),
            Some("Hello, World!\n"),
            Some(vec![("Hello", "World"), ("Powered-By", "proxy-wasm")]),
            Some(-1),
        )
        .execute_and_expect(vec![ReturnType::Action(Action::Pause)])?;

    let http_context = 2;
    http_headers_test
        .call_proxy_on_response_headers(http_context, 0, 0)
        .expect_get_header_map_pairs(Some(MapType::HttpResponseHeaders))
        .returning(Some(vec![(":status", "200"), ("Powered-By", "proxy-wasm")]))
        .expect_log(Some(LogLevel::Trace), Some("#2 <- :status: 200"))
        .expect_log(Some(LogLevel::Trace), Some("#2 <- Powered-By: proxy-wasm"))
        .execute_and_expect(vec![ReturnType::Action(Action::Continue)])?;

    http_headers_test
        .call_proxy_on_log(http_context)
        .expect_log(Some(LogLevel::Trace), Some("#2 completed."))
        .execute_and_expect(vec![ReturnType::None])?;

    return Ok(());
}
