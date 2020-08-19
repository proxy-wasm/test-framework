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
    let mut hello_world_test = tester::mock(args)?;

    hello_world_test
        .call_start()
        .execute_and_expect(vec![ReturnType::None])?;

    let root_context = 1;
    hello_world_test
        .call_proxy_on_context_create(root_context, 0)
        .execute_and_expect(vec![ReturnType::None])?;

    hello_world_test
        .call_proxy_on_vm_start(root_context, 0)
        .expect_log(Some(LogLevel::Info), Some("Hello, World!"))
        .expect_set_tick_period_millis(Some(5 * 10u64.pow(3)))
        .execute_and_expect(vec![ReturnType::Bool(true)])?;

    hello_world_test
        .call_proxy_on_tick(root_context)
        .expect_get_current_time_nanos()
        .returning(Some(0 * 10u64.pow(9)))
        .expect_log(Some(LogLevel::Info), Some("It's 1970-01-01 00:00:00 UTC"))
        .execute_and_expect(vec![ReturnType::None])?;

    hello_world_test
        .call_proxy_on_tick(root_context)
        .execute_and_expect(vec![ReturnType::None])?;

    return Ok(());
}
