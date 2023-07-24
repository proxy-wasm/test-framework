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

use crate::expect_interface::*;
use crate::expectations::ExpectHandle;
use crate::host_settings::HostHandle;
use crate::hostcalls::{generate_import_list, get_abi_version};
use crate::settings_interface::*;
use crate::types::*;

use anyhow::Result;
use std::sync::{Arc, Mutex, MutexGuard};
use structopt::StructOpt;
use wasmtime::*;

#[derive(Debug, StructOpt, Clone)]
#[structopt(
    name = "Mock Settings",
    about = "CLI for Proxy-Wasm Test Framework",
    rename_all = "kebab-case"
)]
pub struct MockSettings {
    pub wasm_path: String,
    #[structopt(short = "q", long)]
    pub quiet: bool,
    #[structopt(short = "a", long)]
    pub allow_unexpected: bool,
}

pub fn mock(mock_settings: MockSettings) -> Result<Tester> {
    // initialize wasm engine and shared cache
    let mut store = Store::<()>::default();
    let module = Module::from_file(store.engine(), &mock_settings.wasm_path)?;

    // generate and link host function implementations
    let abi_version = get_abi_version(&module);
    let imports: Arc<Mutex<Vec<Extern>>> = Arc::new(Mutex::new(Vec::new()));
    let (host_settings, expectations): (Arc<Mutex<HostHandle>>, Arc<Mutex<ExpectHandle>>) =
        generate_import_list(&mut store, &module, imports.clone());
    let instance = Instance::new(&mut store, &module, &(*imports).lock().unwrap()[..])?;

    // create mock test proxy-wasm object
    let tester = Tester::new(
        abi_version,
        mock_settings,
        store,
        instance,
        host_settings,
        expectations,
    );
    return Ok(tester);
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum FunctionCall {
    Start(),
    ProxyOnVmStart(i32, i32),
    ProxyValidateConfiguration(i32, i32),
    ProxyOnConfigure(i32, i32),
    ProxyOnTick(i32),
    ProxyOnForeignFunction(i32, i32, i32),
    ProxyOnQueueReady(i32, i32),
    ProxyOnContextCreate(i32, i32),
    ProxyOnNewConnection(i32),
    ProxyOnDownstreamData(i32, i32, bool),
    ProxyOnDownstreamConnectionClose(i32, i32),
    ProxyOnUpstreamData(i32, i32, bool),
    ProxyOnUpstreamConnectionClose(i32, i32),
    ProxyOnRequestHeaders(i32, i32, bool),
    ProxyOnRequestBody(i32, i32, bool),
    ProxyOnRequestTrailers(i32, i32),
    ProxyOnRequestMetadata(i32, i32),
    ProxyOnResponseHeaders(i32, i32, bool),
    ProxyOnResponseBody(i32, i32, bool),
    ProxyOnResponseTrailers(i32, i32),
    ProxyOnResponseMetadata(i32, i32),
    ProxyOnHttpCallResponse(i32, i32, i32, i32, i32),
    ProxyOnGrpcReceiveInitialMetadata(i32, i32, i32),
    ProxyOnGrpcReceiveTrailingMetadata(i32, i32, i32),
    ProxyOnGrpcReceive(i32, i32, i32),
    ProxyOnGrpcClose(i32, i32, i32),
    ProxyOnDone(i32),
    ProxyOnLog(i32),
    ProxyOnDelete(i32),
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum FunctionType {
    ReturnVoid,
    ReturnBool,
    ReturnAction,
}

pub struct Tester {
    abi_version: AbiVersion,
    mock_settings: MockSettings,
    store: Store<()>,
    instance: Instance,
    defaults: Arc<Mutex<HostHandle>>,
    expect: Arc<Mutex<ExpectHandle>>,
    function_call: Vec<FunctionCall>,
    function_type: Vec<FunctionType>,
}

impl Tester {
    fn new(
        abi_version: AbiVersion,
        mock_settings: MockSettings,
        store: Store<()>,
        instance: Instance,
        host_settings: Arc<Mutex<HostHandle>>,
        expect: Arc<Mutex<ExpectHandle>>,
    ) -> Tester {
        let mut tester = Tester {
            abi_version,
            mock_settings,
            store,
            instance,
            defaults: host_settings,
            expect,
            function_call: vec![],
            function_type: vec![],
        };
        tester.update_expect_stage();
        tester.reset_host_settings();
        tester
    }

    /* ------------------------------------- Low-level Expectation Setting ------------------------------------- */

    pub fn expect_log(&mut self, log_level: Option<LogLevel>, log_msg: Option<&str>) -> &mut Self {
        self.get_expect_handle()
            .staged
            .set_expect_log(log_level.map(|data| data as i32), log_msg);
        self
    }

    pub fn expect_set_tick_period_millis(&mut self, tick_period_millis: Option<u64>) -> &mut Self {
        self.get_expect_handle()
            .staged
            .set_expect_set_tick_period_millis(tick_period_millis);
        self
    }

    pub fn expect_get_current_time_nanos(&mut self) -> ExpectGetCurrentTimeNanos {
        ExpectGetCurrentTimeNanos::expecting(self)
    }

    pub fn expect_get_buffer_bytes(
        &mut self,
        buffer_type: Option<BufferType>,
    ) -> ExpectGetBufferBytes {
        ExpectGetBufferBytes::expecting(self, buffer_type.map(|data| data as i32))
    }

    pub fn expect_set_buffer_bytes(
        &mut self,
        buffer_type: Option<BufferType>,
        buffer_data: Option<&str>,
    ) -> &mut Self {
        self.get_expect_handle()
            .staged
            .set_expect_set_buffer_bytes(buffer_type.map(|data| data as i32), buffer_data);
        self
    }

    pub fn expect_get_header_map_pairs(
        &mut self,
        map_type: Option<MapType>,
    ) -> ExpectGetHeaderMapPairs {
        ExpectGetHeaderMapPairs::expecting(self, map_type.map(|data| data as i32))
    }

    pub fn expect_set_header_map_pairs(
        &mut self,
        map_type: Option<MapType>,
        header_map_pairs: Option<Vec<(&str, &str)>>,
    ) -> &mut Self {
        self.get_expect_handle()
            .staged
            .set_expect_set_header_map_pairs(map_type.map(|data| data as i32), header_map_pairs);
        self
    }

    pub fn expect_get_header_map_value(
        &mut self,
        map_type: Option<MapType>,
        header_map_key: Option<&'static str>,
    ) -> ExpectGetHeaderMapValue {
        ExpectGetHeaderMapValue::expecting(self, map_type.map(|data| data as i32), header_map_key)
    }

    pub fn expect_replace_header_map_value(
        &mut self,
        map_type: Option<MapType>,
        header_map_key: Option<&str>,
        header_map_value: Option<&str>,
    ) -> &mut Self {
        self.get_expect_handle()
            .staged
            .set_expect_replace_header_map_value(
                map_type.map(|data| data as i32),
                header_map_key,
                header_map_value,
            );
        self
    }

    pub fn expect_remove_header_map_value(
        &mut self,
        map_type: Option<MapType>,
        header_map_key: Option<&str>,
    ) -> &mut Self {
        self.get_expect_handle()
            .staged
            .set_expect_remove_header_map_value(map_type.map(|data| data as i32), header_map_key);
        self
    }

    pub fn expect_add_header_map_value(
        &mut self,
        map_type: Option<MapType>,
        header_map_key: Option<&str>,
        header_map_value: Option<&str>,
    ) -> &mut Self {
        self.get_expect_handle()
            .staged
            .set_expect_add_header_map_value(
                map_type.map(|data| data as i32),
                header_map_key,
                header_map_value,
            );
        self
    }

    pub fn expect_send_local_response(
        &mut self,
        status_code: Option<i32>,
        body: Option<&str>,
        headers: Option<Vec<(&str, &str)>>,
        grpc_status: Option<i32>,
    ) -> &mut Self {
        self.get_expect_handle()
            .staged
            .set_expect_send_local_response(status_code, body, headers, grpc_status);
        self
    }

    pub fn expect_http_call(
        &mut self,
        upstream: Option<&'static str>,
        headers: Option<Vec<(&'static str, &'static str)>>,
        body: Option<&'static str>,
        trailers: Option<Vec<(&'static str, &'static str)>>,
        timeout: Option<u64>,
    ) -> ExpectHttpCall {
        ExpectHttpCall::expecting(self, upstream, headers, body, trailers, timeout)
    }

    pub fn expect_grpc_call(
        &mut self,
        service: Option<&'static str>,
        service_name: Option<&'static str>,
        method_name: Option<&'static str>,
        initial_metadata: Option<&'static [u8]>,
        request: Option<&'static [u8]>,
        timeout: Option<u64>,
    ) -> ExpectGrpcCall {
        ExpectGrpcCall::expecting(
            self,
            service,
            service_name,
            method_name,
            initial_metadata,
            request,
            timeout,
        )
    }

    pub fn expect_get_property(&mut self, path: Option<Vec<&'static str>>) -> ExpectGetProperty {
        ExpectGetProperty::expecting(self, path)
    }

    /* ------------------------------------- High-level Expectation Setting ------------------------------------- */

    pub fn set_quiet(&mut self, quiet: bool) {
        self.mock_settings.quiet = quiet;
        self.get_settings_handle().staged.set_quiet_mode(quiet);
    }

    pub fn reset_default_tick_period_millis(&mut self) -> &mut Self {
        self.get_settings_handle().staged.reset_tick_period_millis();
        self
    }

    pub fn set_default_tick_period_millis(&mut self, tick_period_millis: u64) -> &mut Self {
        self.get_settings_handle()
            .staged
            .set_tick_period_millis(tick_period_millis);
        self
    }

    pub fn reset_default_buffer_bytes(&mut self) -> &mut Self {
        self.get_settings_handle().staged.reset_buffer_bytes();
        self
    }

    pub fn set_default_buffer_bytes(&mut self, buffer_type: BufferType) -> DefaultBufferBytes {
        DefaultBufferBytes::expecting(self, buffer_type as i32)
    }

    pub fn reset_default_header_map_pairs(&mut self) -> &mut Self {
        self.get_settings_handle().staged.reset_header_map_pairs();
        self
    }

    pub fn set_default_header_map_pairs(&mut self, map_type: MapType) -> DefaultHeaderMapPairs {
        DefaultHeaderMapPairs::expecting(self, map_type as i32)
    }

    /* ------------------------------------- Utility Functions ------------------------------------- */

    pub fn get_expect_handle(&self) -> MutexGuard<ExpectHandle> {
        self.expect.lock().unwrap()
    }

    pub fn print_expectations(&self) {
        self.expect.lock().unwrap().print_staged();
    }

    fn update_expect_stage(&mut self) {
        self.expect
            .lock()
            .unwrap()
            .update_stage(self.mock_settings.allow_unexpected);
    }

    fn assert_expect_stage(&mut self) {
        let err = self.expect.lock().unwrap().assert_stage();
        if let Some(msg) = err {
            panic!("{}", msg)
        }
    }

    pub fn get_settings_handle(&self) -> MutexGuard<HostHandle> {
        self.defaults.lock().unwrap()
    }

    pub fn print_host_settings(&self) {
        self.defaults.lock().unwrap().print_staged();
    }

    pub fn reset_host_settings(&mut self) {
        self.defaults
            .lock()
            .unwrap()
            .reset(self.abi_version, self.mock_settings.quiet);
    }

    pub fn toggle_strict_mode(&mut self, on: bool) {
        self.expect.lock().unwrap().update_stage(!on);
    }

    /* ------------------------------------- Wasm Function Executation ------------------------------------- */

    pub fn execute_and_expect_n(&mut self, expect_wasm: Vec<ReturnType>) -> Result<()> {
        let mut expect_callback = expect_wasm;
        assert_eq!(self.function_call.len(), expect_callback.len());
        assert_eq!(self.function_call.len(), self.function_type.len());
        assert_ne!(self.function_call.len(), 0);
        while expect_callback.len() > 0 {
            self.execute_and_expect(expect_callback.remove(0))?;
        }
        Ok(())
    }

    pub fn execute_and_expect(&mut self, expect_wasm: ReturnType) -> Result<()> {
        let mut return_wasm: Option<i32> = None;
        match self.function_call.remove(0) {
            FunctionCall::Start() => {
                println!("[host->vm] _start()");
                self.instance
                    .get_typed_func::<(), ()>(&mut self.store, "_start")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `_start` function export"
                    )))?
                    .call(&mut self.store, ())?;
            }

            FunctionCall::ProxyOnVmStart(context_id, vm_configuration_size) => {
                println!(
                    "[host->vm] proxy_on_vm_start(context_id={}, vm_configuration_size={})",
                    context_id, vm_configuration_size
                );
                let success = self
                    .instance
                    .get_typed_func::<(i32, i32), i32>(&mut self.store, "proxy_on_vm_start")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_on_vm_start` function export"
                    )))?
                    .call(&mut self.store, (context_id, vm_configuration_size))?;
                println!("[host<-vm] proxy_on_vm_start return: success={}", success);
                return_wasm = Some(success);
            }

            FunctionCall::ProxyValidateConfiguration(root_context_id, configuration_size) => {
                let proxy_validate_configuration = self
                    .instance
                    .get_typed_func::<(i32, i32), i32>(
                        &mut self.store,
                        "proxy_validate_configuration",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_validate_configuration` function export"
                    )))?;
                println!(
                    "[host->vm] proxy_validate_configuration(root_context_id={}, configuration_size={})",
                    root_context_id, configuration_size
                );
                let success = proxy_validate_configuration
                    .call(&mut self.store, (root_context_id, configuration_size))?;
                println!(
                    "[host<-vm] proxy_validate_configuration return: success={}",
                    success
                );
                return_wasm = Some(success);
            }

            FunctionCall::ProxyOnConfigure(context_id, plugin_configuration_size) => {
                let proxy_on_configure = self
                    .instance
                    .get_typed_func::<(i32, i32), i32>(&mut self.store, "proxy_on_configure")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_configure' function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_configure(context_id={}, plugin_configuration_size={})",
                    context_id, plugin_configuration_size
                );
                let success = proxy_on_configure
                    .call(&mut self.store, (context_id, plugin_configuration_size))?;
                println!("[host<-vm] proxy_on_configure return: success={}", success);
                return_wasm = Some(success);
            }

            FunctionCall::ProxyOnTick(context_id) => {
                let proxy_on_tick = self
                    .instance
                    .get_typed_func::<i32, ()>(&mut self.store, "proxy_on_tick")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_on_tick` function export"
                    )))?;
                println!("[host->vm] proxy_on_tick(context_id={})", context_id);
                proxy_on_tick.call(&mut self.store, context_id)?;
            }

            FunctionCall::ProxyOnForeignFunction(root_context_id, function_id, data_size) => {
                assert_eq!(self.abi_version, AbiVersion::ProxyAbiVersion0_2_0);
                let proxy_on_foreign_function = self
                    .instance
                    .get_typed_func::<(i32, i32, i32), i32>(
                        &mut self.store,
                        "proxy_on_foreign_function",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_foreign_function' function export"
                    )))?;
                println!("[host->vm] proxy_on_foreign_function(root_context_id={}, function_id={}, data_size={})",
                    root_context_id, function_id, data_size);
                let action = proxy_on_foreign_function
                    .call(&mut self.store, (root_context_id, function_id, data_size))?;
                println!(
                    "[host<-vm] proxy_on_foreign_function return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnQueueReady(context_id, queue_id) => {
                let proxy_on_queue_ready = self
                    .instance
                    .get_typed_func::<(i32, i32), ()>(&mut self.store, "proxy_on_queue_ready")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_queue_ready' function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_queue_ready(context_id={}, queue_id={})",
                    context_id, queue_id
                );
                proxy_on_queue_ready.call(&mut self.store, (context_id, queue_id))?;
            }

            // Stream calls
            FunctionCall::ProxyOnContextCreate(root_context_id, parent_context_id) => {
                let proxy_on_context_create = self
                    .instance
                    .get_typed_func::<(i32, i32), ()>(&mut self.store, "proxy_on_context_create")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_on_context_create` function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_context_create(root_context_id={}, parent_context_id={})",
                    root_context_id, parent_context_id
                );
                proxy_on_context_create
                    .call(&mut self.store, (root_context_id, parent_context_id))?;
            }

            FunctionCall::ProxyOnNewConnection(context_id) => {
                let proxy_on_new_connection = self
                    .instance
                    .get_typed_func::<i32, i32>(&mut self.store, "proxy_on_new_connection")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_new_connection' function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_new_connection(context_id={})",
                    context_id
                );
                let action = proxy_on_new_connection.call(&mut self.store, context_id)?;
                println!(
                    "[host<-vm] proxy_on_new_connection return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnDownstreamData(context_id, data_size, end_of_stream) => {
                let proxy_on_downstream_data = self
                    .instance
                    .get_typed_func::<(i32, i32, i32), i32>(
                        &mut self.store,
                        "proxy_on_downstream_data",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_downstream_data' function export"
                    )))?;
                println!(
                        "[host->vm] proxy_on_downstream_data(context_id={}, data_size={}, end_of_stream={})",
                        context_id, data_size, end_of_stream
                    );
                let action = proxy_on_downstream_data.call(
                    &mut self.store,
                    (context_id, data_size, end_of_stream as i32),
                )?;
                println!(
                    "[host<-vm] proxy_on_downstream_data return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnDownstreamConnectionClose(context_id, peer_type) => {
                let proxy_on_downstream_connection_close = self
                    .instance
                    .get_typed_func::<(i32, i32), ()>(&mut self.store, "proxy_on_downstream_connection_close")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_downstream_connection_close' function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_downstream_connection_close(context_id={}, peer_data={})",
                    context_id, peer_type as i32
                );
                proxy_on_downstream_connection_close
                    .call(&mut self.store, (context_id, peer_type))?;
            }

            FunctionCall::ProxyOnUpstreamData(context_id, data_size, end_of_stream) => {
                let proxy_on_upstream_data = self
                    .instance
                    .get_typed_func::<(i32, i32, i32), i32>(
                        &mut self.store,
                        "proxy_on_upstream_data",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_upstream_data' function export"
                    )))?;
                println!(
                        "[host->vm] proxy_on_upstream_data(context_id={}, data_size={}, end_of_stream={})",
                        context_id, data_size, end_of_stream
                    );
                let action = proxy_on_upstream_data.call(
                    &mut self.store,
                    (context_id, data_size, end_of_stream as i32),
                )?;
                println!(
                    "[host<-vm] proxy_on_upstream_data return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnUpstreamConnectionClose(context_id, peer_type) => {
                let proxy_on_upstream_connection_close = self
                    .instance
                    .get_typed_func::<(i32, i32), ()>(
                        &mut self.store,
                        "proxy_on_upstream_connection_close",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_upstream_connection_close' function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_upstream_connection_close(context_id={}, peer_data={})",
                    context_id, peer_type as i32
                );
                proxy_on_upstream_connection_close
                    .call(&mut self.store, (context_id, peer_type))?;
            }

            FunctionCall::ProxyOnRequestHeaders(context_id, num_headers, end_of_stream) => {
                println!(
                    "[host->vm] proxy_on_request_headers(context_id={}, num_headers={}, end_of_stream={})",
                    context_id, num_headers, end_of_stream
                );
                let action = match self.abi_version {
                    AbiVersion::ProxyAbiVersion0_1_0 => {
                        let proxy_on_request_headers = self
                            .instance
                            .get_typed_func::<(i32, i32), i32>(
                                &mut self.store,
                                "proxy_on_request_headers",
                            )
                            .or(Err(anyhow::format_err!(
                                "Error: failed to find `proxy_on_request_headers` function export"
                            )))?;
                        proxy_on_request_headers.call(&mut self.store, (context_id, num_headers))?
                    }
                    AbiVersion::ProxyAbiVersion0_2_0 => {
                        let proxy_on_request_headers = self
                            .instance
                            .get_typed_func::<(i32, i32, i32), i32>(
                                &mut self.store,
                                "proxy_on_request_headers",
                            )
                            .or(Err(anyhow::format_err!(
                                "Error: failed to find `proxy_on_request_headers` function export"
                            )))?;
                        proxy_on_request_headers.call(
                            &mut self.store,
                            (context_id, num_headers, end_of_stream as i32),
                        )?
                    }
                    _ => panic!(
                        "Error: proxy_on_request_headers not supported for {:?}",
                        self.abi_version
                    ),
                };

                println!(
                    "[host<-vm] proxy_on_request_headers return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnRequestBody(context_id, body_size, end_of_stream) => {
                let proxy_on_request_body = self
                    .instance
                    .get_typed_func::<(i32, i32, i32), i32>(
                        &mut self.store,
                        "proxy_on_request_body",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_request_body' function export"
                    )))?;
                println!(
                        "[host->vm] proxy_on_request_body(context_id={}, body_size={}, end_of_stream={})",
                        context_id, body_size, end_of_stream
                    );
                let action = proxy_on_request_body.call(
                    &mut self.store,
                    (context_id, body_size, end_of_stream as i32),
                )?;
                println!("[host<-vm] proxy_on_request_body return: action={}", action);
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnRequestTrailers(context_id, num_trailers) => {
                let proxy_on_request_trailers = self
                    .instance
                    .get_typed_func::<(i32, i32), i32>(&mut self.store, "proxy_on_request_trailers")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_on_request_trailers` function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_request_trailers(context_id={}, num_trailers={})",
                    context_id, num_trailers
                );
                let action =
                    proxy_on_request_trailers.call(&mut self.store, (context_id, num_trailers))?;
                println!(
                    "[host<-vm] proxy_on_request_trailers return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnRequestMetadata(context_id, nelements) => {
                let proxy_on_request_metadata = self
                    .instance
                    .get_typed_func::<(i32, i32), i32>(&mut self.store, "proxy_on_request_metadata")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_on_request_metadata` function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_request_metadata(context_id={}, nelements={})",
                    context_id, nelements
                );
                let action =
                    proxy_on_request_metadata.call(&mut self.store, (context_id, nelements))?;
                println!(
                    "[host<-vm] proxy_on_request_metadata return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnResponseHeaders(context_id, num_headers, end_of_stream) => {
                println!(
                        "[host->vm] proxy_on_response_headers(context_id={}, num_headers={}, end_of_stream={})",
                        context_id, num_headers, end_of_stream
                    );
                let action = match self.abi_version {
                    AbiVersion::ProxyAbiVersion0_1_0 => {
                        let proxy_on_response_headers = self
                            .instance
                            .get_typed_func::<(i32, i32), i32>(
                                &mut self.store,
                                "proxy_on_response_headers",
                            )
                            .or(Err(anyhow::format_err!(
                                "Error: failed to find `proxy_on_response_headers` function export"
                            )))?;
                        proxy_on_response_headers
                            .call(&mut self.store, (context_id, num_headers))?
                    }
                    AbiVersion::ProxyAbiVersion0_2_0 => {
                        let proxy_on_response_headers = self
                            .instance
                            .get_typed_func::<(i32, i32, i32), i32>(
                                &mut self.store,
                                "proxy_on_response_headers",
                            )
                            .or(Err(anyhow::format_err!(
                                "Error: failed to find `proxy_on_response_headers` function export"
                            )))?;
                        proxy_on_response_headers.call(
                            &mut self.store,
                            (context_id, num_headers, end_of_stream as i32),
                        )?
                    }
                    _ => panic!(
                        "Error: proxy_on_response_headers not supported for {:?}",
                        self.abi_version
                    ),
                };
                println!(
                    "[host<-vm] proxy_on_response_headers return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnResponseBody(context_id, body_size, end_of_stream) => {
                let proxy_on_response_body = self
                    .instance
                    .get_typed_func::<(i32, i32, i32), i32>(
                        &mut self.store,
                        "proxy_on_response_body",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_response_body' function export"
                    )))?;
                println!(
                        "[host->vm] proxy_on_response_body(context_id={}, body_size={}, end_of_stream={})",
                        context_id, body_size, end_of_stream
                    );
                let action = proxy_on_response_body.call(
                    &mut self.store,
                    (context_id, body_size, end_of_stream as i32),
                )?;
                println!("[host<-vm] function return: action -> {}", action);
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnResponseTrailers(context_id, num_trailers) => {
                let proxy_on_response_trailers = self
                    .instance
                    .get_typed_func::<(i32, i32), i32>(
                        &mut self.store,
                        "proxy_on_response_trailers",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_on_response_trailers` function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_response_trailers(context_id={}, num_trailers={})",
                    context_id, num_trailers
                );
                let action =
                    proxy_on_response_trailers.call(&mut self.store, (context_id, num_trailers))?;
                println!(
                    "[host<-vm] proxy_on_response_body return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            FunctionCall::ProxyOnResponseMetadata(context_id, nelements) => {
                let proxy_on_response_metadata = self
                    .instance
                    .get_typed_func::<(i32, i32), i32>(
                        &mut self.store,
                        "proxy_on_response_metadata",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_on_response_metadata` function export"
                    )))?;
                println!(
                    "[host->vm] call_proxy_on_response_metadata(context_id={}, nelements={})",
                    context_id, nelements
                );
                let action =
                    proxy_on_response_metadata.call(&mut self.store, (context_id, nelements))?;
                println!(
                    "[host<-vm] proxy_on_response_metadata return: action={}",
                    action
                );
                return_wasm = Some(action);
            }

            // HTTP/gRPC
            FunctionCall::ProxyOnHttpCallResponse(
                context_id,
                callout_id,
                num_headers,
                body_size,
                num_trailers,
            ) => {
                let proxy_on_http_call_response = self
                    .instance
                    .get_typed_func::<(i32, i32, i32, i32, i32), ()>(
                        &mut self.store,
                        "proxy_on_http_call_response",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_on_http_call_response` function export"
                    )))?;
                println!(
                        "[host->vm] proxy_on_http_call_response(context_id={}, callout_id={}, num_headers={}",
                        context_id, callout_id, num_headers
                    );
                println!(
                    "                                       body_size={}, num_trailers={})",
                    body_size, num_trailers
                );
                proxy_on_http_call_response.call(
                    &mut self.store,
                    (context_id, callout_id, num_headers, body_size, num_trailers),
                )?;
            }

            FunctionCall::ProxyOnGrpcReceiveInitialMetadata(context_id, token, headers) => {
                let proxy_on_grpc_receive_initial_metadata = self
                    .instance
                    .get_typed_func::<(i32, i32, i32), ()>(&mut self.store, "proxy_on_grpc_receive_initial_metadata")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_grpc_receive_initial_metadata' function export"
                    )))?;
                println!("[host->vm] proxy_on_grpc_receive_initial_metadata(context_id={}, token={}, headers={})", context_id, token, headers);
                proxy_on_grpc_receive_initial_metadata
                    .call(&mut self.store, (context_id, token, headers))?;
            }

            FunctionCall::ProxyOnGrpcReceiveTrailingMetadata(context_id, token, trailers) => {
                let proxy_on_grpc_trailing_metadata = self
                    .instance
                    .get_typed_func::<(i32, i32, i32), ()>(
                        &mut self.store,
                        "proxy_on_grpc_receive_trailing_metadata",
                    )
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_grpc_trailing_metadata' function export"
                    )))?;
                println!(
                        "[host->vm] proxy_on_grpc_receive_trailing_metadata(context_id={}, token={}, trailers={})",
                        context_id, token, trailers
                    );
                proxy_on_grpc_trailing_metadata
                    .call(&mut self.store, (context_id, token, trailers))?;
            }

            FunctionCall::ProxyOnGrpcReceive(context_id, token, response_size) => {
                let proxy_on_grpc_receive = self
                    .instance
                    .get_typed_func::<(i32, i32, i32), ()>(&mut self.store, "proxy_on_grpc_receive")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_grpc_receive' function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_grpc_receive(context_id={}, token={}, response_size={})",
                    context_id, token, response_size
                );
                proxy_on_grpc_receive.call(&mut self.store, (context_id, token, response_size))?;
            }

            FunctionCall::ProxyOnGrpcClose(context_id, token, status_code) => {
                let proxy_on_grpc_close = self
                    .instance
                    .get_typed_func::<(i32, i32, i32), ()>(&mut self.store, "proxy_on_grpc_close")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_grpc_close' function export"
                    )))?;
                println!(
                    "[host->vm] proxy_on_grpc_close(context_id={}, token={}, status_code={})",
                    context_id, token, status_code
                );
                proxy_on_grpc_close.call(&mut self.store, (context_id, token, status_code))?;
            }

            // The stream/vm has completed
            FunctionCall::ProxyOnDone(context_id) => {
                let proxy_on_done = self
                    .instance
                    .get_typed_func::<i32, i32>(&mut self.store, "proxy_on_done")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_done' function export"
                    )))?;
                println!("[host->vm] proxy_on_done(context_id={})", context_id);
                let is_done = proxy_on_done.call(&mut self.store, context_id)?;
                println!("[host<-vm] proxy_on_done return: is_done={}", is_done);
                return_wasm = Some(is_done);
            }

            FunctionCall::ProxyOnLog(context_id) => {
                let proxy_on_log = self
                    .instance
                    .get_typed_func::<i32, ()>(&mut self.store, "proxy_on_log")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find `proxy_on_log` function export"
                    )))?;
                println!("[host->vm] proxy_on_log(context_id={})", context_id);
                proxy_on_log.call(&mut self.store, context_id)?;
            }

            FunctionCall::ProxyOnDelete(context_id) => {
                let proxy_on_delete = self
                    .instance
                    .get_typed_func::<i32, ()>(&mut self.store, "proxy_on_delete")
                    .or(Err(anyhow::format_err!(
                        "Error: failed to find 'proxy_on_delete' function export"
                    )))?;
                println!("[host->vm] proxy_on_delete(context_id={})", context_id);
                proxy_on_delete.call(&mut self.store, context_id)?;
            }
        }

        match expect_wasm {
            ReturnType::None => {
                assert_eq!(self.function_type.remove(0), FunctionType::ReturnVoid);
                assert_eq!(return_wasm.is_none(), true);
            }
            ReturnType::Bool(expect_bool) => {
                assert_eq!(self.function_type.remove(0), FunctionType::ReturnBool);
                assert_eq!(expect_bool as i32, return_wasm.unwrap_or(-1));
            }
            ReturnType::Action(expect_action) => {
                assert_eq!(self.function_type.remove(0), FunctionType::ReturnAction);
                assert_eq!(expect_action as i32, return_wasm.unwrap_or(-1));
            }
        }

        if self.function_call.len() == 0 {
            self.assert_expect_stage();
            self.update_expect_stage();
        }

        println!("\n");
        Ok(())
    }

    /* ------------------------------------- Calls in setting ------------------------------------- */

    pub fn call_start(&mut self) -> &mut Self {
        self.function_call.push(FunctionCall::Start());
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn call_proxy_on_vm_start(
        &mut self,
        context_id: i32,
        vm_configuration_size: i32,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnVmStart(
            context_id,
            vm_configuration_size,
        ));
        self.function_type.push(FunctionType::ReturnBool);
        self
    }

    pub fn call_proxy_validate_configuration(
        &mut self,
        root_context_id: i32,
        configuration_size: i32,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyValidateConfiguration(
                root_context_id,
                configuration_size,
            ));
        self.function_type.push(FunctionType::ReturnBool);
        self
    }

    pub fn call_proxy_on_configure(
        &mut self,
        context_id: i32,
        plugin_configuration_size: i32,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnConfigure(
            context_id,
            plugin_configuration_size,
        ));
        self.function_type.push(FunctionType::ReturnBool);
        self
    }

    pub fn call_proxy_on_tick(&mut self, context_id: i32) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnTick(context_id));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn call_proxy_on_foreign_function(
        &mut self,
        root_context_id: i32,
        function_id: i32,
        data_size: i32,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnForeignFunction(
                root_context_id,
                function_id,
                data_size,
            ));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_queue_ready(&mut self, context_id: i32, queue_id: i32) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnQueueReady(context_id, queue_id));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    // Stream calls
    pub fn call_proxy_on_context_create(
        &mut self,
        root_context_id: i32,
        parent_context_id: i32,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnContextCreate(
            root_context_id,
            parent_context_id,
        ));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn call_proxy_on_new_connection(&mut self, context_id: i32) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnNewConnection(context_id));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_downstream_data(
        &mut self,
        context_id: i32,
        data_size: i32,
        end_of_stream: bool,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnDownstreamData(
            context_id,
            data_size,
            end_of_stream,
        ));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_downstream_connection_close(
        &mut self,
        context_id: i32,
        peer_type: PeerType,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnDownstreamConnectionClose(
                context_id,
                peer_type as i32,
            ));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn call_proxy_on_upstream_data(
        &mut self,
        context_id: i32,
        data_size: i32,
        end_of_stream: bool,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnUpstreamData(
            context_id,
            data_size,
            end_of_stream,
        ));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_upstream_connection_close(
        &mut self,
        context_id: i32,
        peer_type: PeerType,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnUpstreamConnectionClose(
                context_id,
                peer_type as i32,
            ));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn call_proxy_on_request_headers(
        &mut self,
        context_id: i32,
        num_headers: i32,
        end_of_stream: bool,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnRequestHeaders(
            context_id,
            num_headers,
            end_of_stream,
        ));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_request_body(
        &mut self,
        context_id: i32,
        body_size: i32,
        end_of_stream: bool,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnRequestBody(
            context_id,
            body_size,
            end_of_stream,
        ));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_request_trailers(
        &mut self,
        context_id: i32,
        num_trailers: i32,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnRequestTrailers(
                context_id,
                num_trailers,
            ));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_request_metadata(&mut self, context_id: i32, nelements: i32) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnRequestMetadata(context_id, nelements));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_response_headers(
        &mut self,
        context_id: i32,
        num_headers: i32,
        end_of_stream: bool,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnResponseHeaders(
                context_id,
                num_headers,
                end_of_stream,
            ));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_response_body(
        &mut self,
        context_id: i32,
        body_size: i32,
        end_of_stream: bool,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnResponseBody(
            context_id,
            body_size,
            end_of_stream,
        ));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_response_trailers(
        &mut self,
        context_id: i32,
        num_trailers: i32,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnResponseTrailers(
                context_id,
                num_trailers,
            ));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    pub fn call_proxy_on_response_metadata(
        &mut self,
        context_id: i32,
        nelements: i32,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnResponseMetadata(context_id, nelements));
        self.function_type.push(FunctionType::ReturnAction);
        self
    }

    // HTTP/gRPC
    pub fn call_proxy_on_http_call_response(
        &mut self,
        context_id: i32,
        callout_id: i32,
        num_headers: i32,
        body_size: i32,
        num_trailers: i32,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnHttpCallResponse(
                context_id,
                callout_id,
                num_headers,
                body_size,
                num_trailers,
            ));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn call_proxy_on_grpc_receive_initial_metadata(
        &mut self,
        context_id: i32,
        token: i32,
        headers: i32,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnGrpcReceiveInitialMetadata(
                context_id, token, headers,
            ));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn call_proxy_on_grpc_receive_trailing_metadata(
        &mut self,
        context_id: i32,
        token: i32,
        trailers: i32,
    ) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnGrpcReceiveTrailingMetadata(
                context_id, token, trailers,
            ));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn call_proxy_on_grpc_receive(
        &mut self,
        context_id: i32,
        token: i32,
        response_size: i32,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnGrpcReceive(
            context_id,
            token,
            response_size,
        ));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn proxy_on_grpc_close(
        &mut self,
        context_id: i32,
        token: i32,
        status_code: i32,
    ) -> &mut Self {
        self.function_call.push(FunctionCall::ProxyOnGrpcClose(
            context_id,
            token,
            status_code,
        ));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    // The stream/vm has completed
    pub fn call_proxy_on_done(&mut self, context_id: i32) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnDone(context_id));
        self.function_type.push(FunctionType::ReturnBool);
        self
    }

    pub fn call_proxy_on_log(&mut self, context_id: i32) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnLog(context_id));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    pub fn call_proxy_on_delete(&mut self, context_id: i32) -> &mut Self {
        self.function_call
            .push(FunctionCall::ProxyOnDelete(context_id));
        self.function_type.push(FunctionType::ReturnVoid);
        self
    }

    /* ---------------------------------- Combination Calls ---------------------------------- */
    pub fn http_request(
        &mut self,
        http_context: i32,
        headers: Option<Vec<(&str, &str)>>,
        body: Option<&str>,
        trailers: Option<Vec<(&str, &str)>>,
    ) -> Result<&mut Self> {
        self.toggle_strict_mode(false);
        let mut headers = headers;
        let mut body = body;
        let mut trailers = trailers;
        let end_of_stream = false;
        if let Some(header_map_pairs) = headers.take() {
            let num_headers = header_map_pairs.len() as i32;
            self.set_default_header_map_pairs(MapType::HttpRequestHeaders)
                .returning(header_map_pairs)
                .call_proxy_on_request_headers(http_context, num_headers, end_of_stream);
        }

        if let Some(body_data) = body.take() {
            let body_size = body_data.len() as i32;
            self.set_default_buffer_bytes(BufferType::HttpRequestBody)
                .returning(body_data)
                .call_proxy_on_request_body(http_context, body_size, end_of_stream);
        }

        if let Some(header_map_pairs) = trailers.take() {
            let num_trailers = header_map_pairs.len() as i32;
            self.set_default_header_map_pairs(MapType::HttpRequestTrailers)
                .returning(header_map_pairs)
                .call_proxy_on_request_trailers(http_context, num_trailers);
        }
        Ok(self)
    }

    pub fn http_response(
        &mut self,
        http_context: i32,
        headers: Option<Vec<(&str, &str)>>,
        body: Option<&str>,
        trailers: Option<Vec<(&str, &str)>>,
    ) -> Result<&mut Self> {
        self.toggle_strict_mode(false);
        let mut headers = headers;
        let mut body = body;
        let mut trailers = trailers;
        let end_of_stream = false;
        if let Some(header_map_pairs) = headers.take() {
            let num_headers = header_map_pairs.len() as i32;
            self.set_default_header_map_pairs(MapType::HttpResponseHeaders)
                .returning(header_map_pairs)
                .call_proxy_on_response_headers(http_context, num_headers, end_of_stream);
        }

        if let Some(body_data) = body.take() {
            let body_size = body_data.len() as i32;
            self.set_default_buffer_bytes(BufferType::HttpResponseBody)
                .returning(body_data)
                .call_proxy_on_response_body(http_context, body_size, end_of_stream);
        }

        if let Some(header_map_pairs) = trailers.take() {
            let num_trailers = header_map_pairs.len() as i32;
            self.set_default_header_map_pairs(MapType::HttpResponseTrailers)
                .returning(header_map_pairs)
                .call_proxy_on_response_trailers(http_context, num_trailers);
        }
        Ok(self)
    }
}
