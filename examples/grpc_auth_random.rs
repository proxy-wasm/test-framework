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
    let mut module = tester::mock(args)?;

    module.call_start().execute_and_expect(ReturnType::None)?;

    let root_context = 1;
    module
        .call_proxy_on_context_create(root_context, 0)
        .execute_and_expect(ReturnType::None)?;

    let http_context = 2;
    module
        .call_proxy_on_context_create(http_context, root_context)
        .execute_and_expect(ReturnType::None)?;

    let token_id = 42;
    module
        .call_proxy_on_request_headers(http_context, 0, false)
        .expect_get_header_map_value(Some(MapType::HttpRequestHeaders), Some("content-type"))
        .returning(Some("application/grpc"))
        .expect_get_header_map_value(Some(MapType::HttpRequestHeaders), Some(":path"))
        .returning(Some("/someService/someService.someMethod"))
        .expect_grpc_call(
            Some("grpcbin"),
            Some("grpcbin.GRPCBin"),
            Some("RandomError"),
            Some(&[0, 0, 0, 0]),
            Some(&[]),
            Some(1000), // 1 sec as millis
        )
        .returning(Some(token_id))
        .execute_and_expect(ReturnType::Action(Action::Pause))?;

    module
        .call_proxy_on_grpc_receive(http_context, token_id as i32, 0 as i32)
        .expect_log(Some(LogLevel::Info), Some("Access granted."))
        .execute_and_expect(ReturnType::None)?;

    module
        .call_proxy_on_response_headers(http_context, 0, false)
        .expect_replace_header_map_value(
            Some(MapType::HttpResponseHeaders),
            Some("Powered-By"),
            Some("proxy-wasm"),
        )
        .execute_and_expect(ReturnType::Action(Action::Continue))?;

    return Ok(());
}
