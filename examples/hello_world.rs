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
    let hello_world = "/usr/local/google/home/chrisagia/ws/proxy-wasm-rust-sdk/target\
                       /wasm32-unknown-unknown/release/examples/hello_world.wasm";

    let mut hello_world_test = tester::test(hello_world)?;

    hello_world_test
        .call_start()
        .execute_and_expect(ReturnType::None)?;

    hello_world_test
        .call_proxy_on_context_create(1, 0)
        .execute_and_expect(ReturnType::None)?;

    hello_world_test
        .call_proxy_on_vm_start(1, 0)
        .expect_log(LogLevel::Info, "Hello, World!")
        .expect_set_tick_period_millis(5 * 10u64.pow(3))
        .execute_and_expect(ReturnType::Bool(true))?;

    hello_world_test
        .call_proxy_on_tick(1)
        .expect_get_current_time_nanos()
        .returning(0 * 10u64.pow(9))
        .execute_and_expect(ReturnType::None)?;

    hello_world_test
        .call_proxy_on_tick(1)
        .execute_and_expect(ReturnType::None)?;

    return Ok(());
}
