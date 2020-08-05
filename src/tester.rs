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


use crate::types::*;
use crate::expectations::ExpectHandle;
use crate::host_settings::HostHandle;
use crate::expect_interface::*;
use crate::settings_interface::*;
use crate::hostcalls::generate_import_list;

use wasmtime::*;
use std::sync::{Arc, Mutex, MutexGuard};
use anyhow::Result;


pub fn test(wasm_file: &str) -> Result<Tester> {

    // initialize wasm engine and shared cache
    let store = Store::default();    
    let module = Module::from_file(store.engine(), wasm_file)?;

    // generate and link host function implementations
    let imports: Arc<Mutex<Vec<Extern>>> = Arc::new(Mutex::new(Vec::new()));
    let (host_settings, expectations): (Arc<Mutex<HostHandle>>, Arc<Mutex<ExpectHandle>>) = generate_import_list(&store, &module, imports.clone());
    let instance = Instance::new(&store, &module, &(*imports).lock().unwrap()[..])?;

    // create mock test proxy-wasm object
    let tester = Tester::new(instance, host_settings, expectations);
    return Ok(tester);

}


#[derive(Debug)]
enum FunctionCall {
    Empty(),
    Start(),
    ProxyOnContextCreate(i32, i32),
    ProxyOnLog(i32),
    ProxyOnDone(i32),
    ProxyOnDelete(i32),
    ProxyOnVmStart(i32, i32),
    ProxyOnConfigure(i32, i32),
    ProxyOnTick(i32),
    ProxyOnQueueReady(i32, i32),
    ProxyOnNewConnection(i32),
    ProxyOnDownstreamData(i32, i32, i32),
    ProxyOnDownstreamConnectionClose(i32, i32),
    ProxyOnUpstreamData(i32, i32, i32),
    ProxyOnUpstreamConnectionClose(i32, i32),
    ProxyOnRequestHeaders(i32, i32),
    ProxyOnRequestBody(i32, i32, i32),
    ProxyOnRequestTrailers(i32, i32),
    ProxyOnResponseHeaders(i32, i32),
    ProxyOnResponseBody(i32, i32, i32),
    ProxyOnResponseTrailers(i32, i32),
    ProxyOnHttpCallResponse(i32, i32, i32, i32, i32),
}

#[derive(Debug)]
enum FunctionType {
    ReturnEmpty,
    ReturnBool,
    ReturnAction,
}


pub struct Tester {
    function_type: FunctionType,
    function_call: FunctionCall,
    instance: Instance,
    defaults: Arc<Mutex<HostHandle>>,
    expect: Arc<Mutex<ExpectHandle>>,
}


impl Tester {

    fn new(instance: Instance, host_settings: Arc<Mutex<HostHandle>>, expect: Arc<Mutex<ExpectHandle>>) 
    -> Tester {
        Tester {
            function_type: FunctionType::ReturnEmpty,
            function_call: FunctionCall::Empty(),
            instance: instance,
            defaults: host_settings,
            expect: expect,
        }
    }

    /* ------------------------------------- Low-level Expectation Setting ------------------------------------- */

    pub fn expect_log(&mut self, log_level: LogLevel, log_msg: &str) -> &mut Self {
        self.get_expect_handle().staged.set_expect_log(log_level as i32, log_msg);
        self
    } 

    pub fn expect_set_tick_period_millis(&mut self, tick_period_millis: u64) -> &mut Self {
        self.get_expect_handle().staged.set_expect_set_tick_period_millis(tick_period_millis);       
        self
    }

    pub fn expect_get_current_time_nanos(&mut self) -> ExpectGetCurrentTimeNanos {
        ExpectGetCurrentTimeNanos::expecting(self)
    }

    pub fn expect_get_buffer_bytes(&mut self, buffer_type: BufferType) -> ExpectGetBufferBytes {
        ExpectGetBufferBytes::expecting(self, buffer_type as i32)
    }

    pub fn expect_get_header_map_pairs(&mut self, map_type: MapType) -> ExpectGetHeaderMapPairs {
        ExpectGetHeaderMapPairs::expecting(self, map_type as i32)
    }

    pub fn expect_set_header_map_pairs(&mut self, map_type: MapType) -> ExpectSetHeaderMapPairs {
        ExpectSetHeaderMapPairs::expecting(self, map_type as i32)
    }

    pub fn expect_get_header_map_value(&mut self, map_type: MapType, header_map_key: &'static str) -> ExpectGetHeaderMapValue {
        ExpectGetHeaderMapValue::expecting(self, map_type as i32, header_map_key)
    }

    pub fn expect_replace_header_map_value(&mut self, map_type: MapType, header_map_key: &str, header_map_value: &str) -> &mut Self {
        self.get_expect_handle().staged.set_expect_replace_header_map_value(map_type as i32, header_map_key, header_map_value);
        self
    }

    pub fn expect_remove_header_map_value(&mut self, map_type: MapType, header_map_key: &str) -> &mut Self {
        self.get_expect_handle().staged.set_expect_remove_header_map_value(map_type as i32, header_map_key);
        self
    } 

    pub fn expect_add_header_map_value(&mut self, map_type: MapType, header_map_key: &str, header_map_value: &str) -> &mut Self {
        self.get_expect_handle().staged.set_expect_add_header_map_value(map_type as i32, header_map_key, header_map_value);
        self
    }

    pub fn expect_set_send_local_response(&mut self, status_code: i32, body: &str, headers: Vec<(&str, &str)>, grpc_status: i32) -> &mut Self {
        self.get_expect_handle().staged.set_expect_send_local_response(status_code, body, headers, grpc_status);
        self
    }

    pub fn expect_set_http_call(&mut self, upstream: &'static str, headers: Vec<(&'static str, &'static str)>, body: &'static str, 
        trailers: Vec<(&'static str, &'static str)>, timeout: u64) -> ExpectHttpCall {
            ExpectHttpCall::expecting(self, upstream, headers, body, trailers, timeout)
    }

    /* ------------------------------------- High-level Expectation Setting ------------------------------------- */

    pub fn reset_default_tick_period_millis(&mut self) -> &mut Self {
        self.get_settings_handle().staged.reset_tick_period_millis();
        self
    }

    pub fn set_default_tick_period_millis(&mut self, tick_period_millis: u64) -> &mut Self {
        self.get_settings_handle().staged.set_tick_period_millis(tick_period_millis);
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
        self.expect.lock().unwrap().update_stage();
    }

    fn assert_expect_stage(&mut self) {
        self.expect.lock().unwrap().assert_stage();
    }
        
    pub fn get_settings_handle(&self) -> MutexGuard<HostHandle> {
        self.defaults.lock().unwrap()
    }

    pub fn print_host_settings(&self) {
        self.defaults.lock().unwrap().print_staged();
    }

    pub fn reset_host_settings(&mut self) {
        self.defaults.lock().unwrap().reset();
    }

    /* ------------------------------------- Wasm Function Executation ------------------------------------- */

    // pub fn execute(&mut self) -> Box<dyn WasmExpect> {
    //     match self.function_type {
    //         FunctionType::ReturnEmpty => {return ExpectNone::new(self);},
    //         FunctionType::ReturnBool => {return ExpectBool::new(self);},
    //         FunctionType::ReturnAction => {return ExpectAction::new(self);},
    //     }
    // } 

    pub fn execute_and_expect(&mut self, expect_wasm: Option<i32>) -> Result<()> {

        let mut return_wasm: Option<i32> = None;
        match self.function_call {

            FunctionCall::Start() => {
                let _start = self.instance.get_func("_start")
                    .ok_or(anyhow::format_err!("failed to find `_start` function export"))?
                    .get0::<()>()?;
                _start()?;
            },

            FunctionCall::ProxyOnContextCreate(root_context_id, parent_context_id) => {
                let proxy_on_context_create = self.instance.get_func("proxy_on_context_create")
                    .ok_or(anyhow::format_err!("failed to find `proxy_on_context_create` function export"))?
                    .get2::<i32, i32, ()>()?;
                proxy_on_context_create(root_context_id, parent_context_id)?;
            },

            FunctionCall::ProxyOnDone(context_id) => {
                let proxy_on_done = self.instance.get_func("proxy_on_done")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_done' function export"))?
                    .get1::<i32, i32>()?;
                let is_done = proxy_on_done(context_id)?;
                println!("RETURN:    is_done -> {}", is_done);
                return_wasm = Some(is_done);
            },

            FunctionCall::ProxyOnLog(context_id) => {
                let proxy_on_log = self.instance.get_func("proxy_on_log")
                    .ok_or(anyhow::format_err!("failed to find `proxy_on_log` function export"))?
                    .get1::<i32, ()>()?;
                proxy_on_log(context_id)?;
            },

            FunctionCall::ProxyOnDelete(context_id) => {
                let proxy_on_delete = self.instance.get_func("proxy_on_delete")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_delete' function export"))?
                    .get1::<i32, ()>()?;
                proxy_on_delete(context_id)?;
            },

            FunctionCall::ProxyOnVmStart(context_id, vm_configuration_size) => {
                let proxy_on_vm_start = self.instance.get_func("proxy_on_vm_start")
                    .ok_or(anyhow::format_err!("failed to find `proxy_on_vm_start` function export"))?
                    .get2::<i32, i32, i32>()?;
                let success = proxy_on_vm_start(context_id, vm_configuration_size)?;
                println!("RETURN:    success -> {}", success);
                return_wasm = Some(success);
            },

            FunctionCall::ProxyOnConfigure(context_id, plugin_configuration_size) => {
                let proxy_on_configure = self.instance.get_func("proxy_on_configure")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_configure' function export"))?
                    .get2::<i32, i32, i32>()?;
                let success = proxy_on_configure(context_id, plugin_configuration_size)?;
                println!("RETURN:    success -> {}", success);
                return_wasm = Some(success);
            },

            FunctionCall::ProxyOnTick(context_id) => {
                let proxy_on_tick = self.instance.get_func("proxy_on_tick")
                    .ok_or(anyhow::format_err!("failed to find `proxy_on_tick` function export"))?
                    .get1::<i32, ()>()?;
                proxy_on_tick(context_id)?;
            },

            FunctionCall::ProxyOnQueueReady(context_id, queue_id) => {
                let proxy_on_queue_ready = self.instance.get_func("proxy_on_queue_ready")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_queue_ready' function export"))?
                    .get2::<i32, i32, ()>()?;
                proxy_on_queue_ready(context_id, queue_id)?;
            },

            FunctionCall::ProxyOnNewConnection(context_id) => {
                let proxy_on_new_connection = self.instance.get_func("proxy_on_new_connection")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_new_connection' function export"))?
                    .get1::<i32, i32>()?;
                let action = proxy_on_new_connection(context_id)?;
                println!("RETURN:    action -> {}", action);
                return_wasm = Some(action);
            },

            FunctionCall::ProxyOnDownstreamData(context_id, data_size, end_of_stream) => {
                let proxy_on_downstream_data = self.instance.get_func("proxy_on_downstream_data")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_downstream_data' function export"))?
                    .get3::<i32, i32, i32, i32>()?;
                let action = proxy_on_downstream_data(context_id, data_size, end_of_stream)?;
                println!("RETURN:    action -> {}", action);
                return_wasm = Some(action);
            },

            FunctionCall::ProxyOnDownstreamConnectionClose(context_id, peer_type) => {
                let proxy_on_downstream_connection_close = self.instance.get_func("proxy_on_downstream_connection_close")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_downstream_connection_close' function export"))?
                    .get2::<i32, i32, ()>()?;
                proxy_on_downstream_connection_close(context_id, peer_type)?;
            },

            FunctionCall::ProxyOnUpstreamData(context_id, data_size, end_of_stream) => {
                let proxy_on_upstream_data = self.instance.get_func("proxy_on_upstream_data")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_upstream_data' function export"))?
                    .get3::<i32, i32, i32, i32>()?;
                let action = proxy_on_upstream_data(context_id, data_size, end_of_stream)?;
                println!("RETURN:    action -> {}", action);
                return_wasm = Some(action);
            },

            FunctionCall::ProxyOnUpstreamConnectionClose(context_id, peer_type) => {
                let proxy_on_upstream_connection_close = self.instance.get_func("proxy_on_upstream_connection_close")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_upstream_connection_close' function export"))?
                    .get2::<i32, i32, ()>()?;
                    proxy_on_upstream_connection_close(context_id, peer_type)?;
            },
 
            FunctionCall::ProxyOnRequestHeaders(context_id, num_headers) => {
                let proxy_on_request_headers = self.instance.get_func("proxy_on_request_headers")
                    .ok_or(anyhow::format_err!("failed to find `proxy_on_request_headers` function export"))?
                    .get2::<i32, i32, i32>()?;
                let action = proxy_on_request_headers(context_id, num_headers)?;
                println!("RETURN:    action -> {}", action);
                return_wasm = Some(action);
            },

            FunctionCall::ProxyOnRequestBody(context_id, body_size, end_of_stream) => {
                let proxy_on_request_body = self.instance.get_func("proxy_on_request_body")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_request_body' function export"))?
                    .get3::<i32, i32, i32, i32>()?;
                let action = proxy_on_request_body(context_id, body_size, end_of_stream)?;
                println!("RETURN:    action -> {}", action);
                return_wasm = Some(action);
            },

            FunctionCall::ProxyOnRequestTrailers(context_id, num_trailers) => {
                let proxy_on_request_trailers = self.instance.get_func("proxy_on_request_trailers")
                    .ok_or(anyhow::format_err!("failed to find `proxy_on_request_trailers` function export"))?
                    .get2::<i32, i32, i32>()?;
                let action = proxy_on_request_trailers(context_id, num_trailers)?;
                println!("RETURN:    action -> {}", action);
                return_wasm = Some(action);
            },

            FunctionCall::ProxyOnResponseHeaders(context_id, num_headers) => {
                let proxy_on_response_headers = self.instance.get_func("proxy_on_response_headers")
                    .ok_or(anyhow::format_err!("failed to find `proxy_on_response_headers` function export"))?
                    .get2::<i32, i32, i32>()?;
                let action = proxy_on_response_headers(context_id, num_headers)?;
                println!("RETURN:    action -> {}", action);
                return_wasm = Some(action);
            },

            FunctionCall::ProxyOnResponseBody(context_id, body_size, end_of_stream) => {
                let proxy_on_response_body = self.instance.get_func("proxy_on_response_body")
                    .ok_or(anyhow::format_err!("failed to find 'proxy_on_response_body' function export"))?
                    .get3::<i32, i32, i32, i32>()?;
                let action = proxy_on_response_body(context_id, body_size, end_of_stream)?;
                println!("RETURN:    action -> {}", action);
                return_wasm = Some(action);
            },

            FunctionCall::ProxyOnResponseTrailers(context_id, num_trailers) => {
                let proxy_on_response_trailers = self.instance.get_func("proxy_on_response_trailers")
                    .ok_or(anyhow::format_err!("failed to find `proxy_on_response_trailers` function export"))?
                    .get2::<i32, i32, i32>()?;
                let action = proxy_on_response_trailers(context_id, num_trailers)?;
                println!("RETURN:    action -> {}", action);
                return_wasm = Some(action);
            },

            FunctionCall::ProxyOnHttpCallResponse(context_id, callout_id, num_headers, body_size, num_trailers) => {
                let proxy_on_http_call_response = self.instance.get_func("proxy_on_http_call_response")
                    .ok_or(anyhow::format_err!("failed to find `proxy_on_http_call_response` function export"))?
                    .get5::<i32, i32, i32, i32, i32, ()>()?;
                proxy_on_http_call_response(context_id, callout_id, num_headers, body_size, num_trailers)?;
            },

            _ => panic!("No function with name: {:?}", self.function_call),
        }    

        if (expect_wasm == None && return_wasm != None) || (expect_wasm != None && return_wasm == None) {
            panic!("Error calling {:?}: Expected return type does not match actual return type", self.function_call);
        } else if expect_wasm != None && return_wasm != None {
            if expect_wasm.unwrap() != return_wasm.unwrap() {
                panic!("Error calling {:?}: Expected return did not match actual return", self.function_call);
            }
        }

        self.assert_expect_stage();        
        self.update_expect_stage();
        println!("\n");
        return Ok(()); 
    }

    /* ------------------------------------- Call Setting ------------------------------------- */

    pub fn call_start(&mut self) -> &mut Self {
        println!("CALL TO:   _start");
        self.function_call = FunctionCall::Start();
        self
    }

    pub fn call_proxy_on_context_create(&mut self, root_context_id: i32, parent_context_id: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_context_create");
        println!("ARGS:      root_context_id -> {}, parent_context_id -> {}", root_context_id, parent_context_id);
        self.function_call = FunctionCall::ProxyOnContextCreate(root_context_id, parent_context_id);
        self
    }

    pub fn call_proxy_on_done(&mut self, context_id: i32) -> &mut Self{
        println!("CALL TO:   proxy_on_done");
        println!("ARGS:      context_id -> {}", context_id);
        self.function_call = FunctionCall::ProxyOnDone(context_id);
        self
    }

    pub fn call_proxy_on_log(&mut self, context_id: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_log");
        println!("ARGS:      context_id -> {}", context_id);
        self.function_call = FunctionCall::ProxyOnLog(context_id);
        self
    }

    pub fn call_proxy_on_delete(&mut self, context_id: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_delete");
        println!("ARGS:      context_id -> {}", context_id);
        self.function_call = FunctionCall::ProxyOnDelete(context_id);
        self
    }

    pub fn call_proxy_on_vm_start(&mut self, context_id: i32, vm_configuration_size: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_vm_start");
        println!("ARGS:      context_id -> {}, vm_configuration_size -> {}", context_id, vm_configuration_size);
        self.function_call = FunctionCall::ProxyOnVmStart(context_id, vm_configuration_size);
        self
    }

    pub fn call_proxy_on_configure(&mut self, context_id: i32, plugin_configuration_size: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_configure");
        println!("ARGS:      context_id -> {}, plugin_configuration_size -> {}", context_id, plugin_configuration_size);
        self.function_call = FunctionCall::ProxyOnConfigure(context_id, plugin_configuration_size);
        self
    }

    pub fn call_proxy_on_tick(&mut self, context_id: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_tick");
        println!("ARGS:      context_id -> {}", context_id);
        self.function_call = FunctionCall::ProxyOnTick(context_id);
        self
    }

    pub fn call_proxy_on_queue_ready(&mut self, context_id: i32, queue_id: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_queue_ready");
        println!("ARGS:      context_id -> {}, queue_id -> {}", context_id, queue_id);
        self.function_call = FunctionCall::ProxyOnQueueReady(context_id, queue_id);
        self
    }

    pub fn call_proxy_on_new_connection(&mut self, context_id: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_new_connection");
        println!("ARGS:      context_id -> {}", context_id);
        self.function_call = FunctionCall::ProxyOnNewConnection(context_id);
        self
    }

    pub fn call_proxy_on_downstream_data(&mut self, context_id: i32, data_size: i32, end_of_stream: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_downstream_data");
        println!("ARGS:      context_id -> {}, data_size -> {}, end_of_stream -> {}", context_id, data_size, end_of_stream);
        self.function_call = FunctionCall::ProxyOnDownstreamData(context_id, data_size, end_of_stream);
        self
    }

    pub fn call_proxy_on_downstream_connection_close(&mut self, context_id: i32, peer_type: PeerType) -> &mut Self {
        println!("CALL TO:   proxy_on_downstream_connection_close");
        println!("ARGS:      context_id -> {}, peer_data -> {}", context_id, peer_type as i32);
        self.function_call = FunctionCall::ProxyOnDownstreamConnectionClose(context_id, peer_type as i32);
        self
    }

    pub fn call_proxy_on_upstream_data(&mut self, context_id: i32, data_size: i32, end_of_stream: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_upstream_data");
        println!("ARGS:      context_id -> {}, data_size -> {}, end_of_stream -> {}", context_id, data_size, end_of_stream);
        self.function_call = FunctionCall::ProxyOnUpstreamData(context_id, data_size, end_of_stream);
        self
    }

    pub fn call_proxy_on_upstream_connection_close(&mut self, context_id: i32, peer_type: PeerType) -> &mut Self {
        println!("CALL TO:   proxy_on_upstream_connection_close");
        println!("ARGS:      context_id -> {}, peer_data -> {}", context_id, peer_type as i32);
        self.function_call = FunctionCall::ProxyOnUpstreamConnectionClose(context_id, peer_type as i32);
        self
    }

    pub fn call_proxy_on_request_headers(&mut self, context_id: i32, num_headers: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_request_headers");
        println!("ARGS:      context_id -> {}, num_headers -> {}", context_id, num_headers);
        self.function_call = FunctionCall::ProxyOnRequestHeaders(context_id, num_headers);
        self
    }

    pub fn call_proxy_on_request_body(&mut self, context_id: i32, body_size: i32, end_of_stream: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_request_body");
        println!("ARGS:      context_id -> {}, body_size -> {}, end_of_stream -> {}", context_id, body_size, end_of_stream);
        self.function_call = FunctionCall::ProxyOnRequestBody(context_id, body_size, end_of_stream);
        self
    }

    pub fn call_proxy_on_request_trailers(&mut self, context_id: i32, num_trailers: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_request_trailers");
        println!("ARGS:      context_id -> {}, num_trailers -> {}", context_id, num_trailers);
        self.function_call = FunctionCall::ProxyOnRequestTrailers(context_id, num_trailers);
        self
    }
    
    pub fn call_proxy_on_response_headers(&mut self, context_id: i32, num_headers: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_response_headers");
        println!("ARGS:      context_id -> {}, num_headers -> {}", context_id, num_headers);
        self.function_call = FunctionCall::ProxyOnResponseHeaders(context_id, num_headers);
        self
    }

    pub fn call_proxy_on_response_body(&mut self, context_id: i32, body_size: i32, end_of_stream: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_response_body");
        println!("ARGS:      context_id -> {}, body_size -> {}, end_of_stream -> {}", context_id, body_size, end_of_stream);
        self.function_call = FunctionCall::ProxyOnResponseBody(context_id, body_size, end_of_stream);
        self
    }

    pub fn call_proxy_on_response_trailers(&mut self, context_id: i32, num_trailers: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_response_trailers");
        println!("ARGS:      context_id -> {}, num_trailers -> {}", context_id, num_trailers);
        self.function_call = FunctionCall::ProxyOnResponseTrailers(context_id, num_trailers);
        self
    }

    pub fn call_proxy_on_http_call_response(&mut self, context_id: i32, callout_id: i32, num_headers: i32, 
                                            body_size: i32, num_trailers: i32) -> &mut Self {
        println!("CALL TO:   proxy_on_http_call_response");
        println!("ARGS:      context_id -> {}, callout_id -> {}", context_id, callout_id);
        println!("           num_headers -> {}, body_size -> {}, num_trailers: {}", num_headers, body_size, num_trailers);
        self.function_call = FunctionCall::ProxyOnHttpCallResponse(context_id, callout_id, num_headers, 
                                                                   body_size, num_trailers);
        self
    }

    /* ---------------------------------- Combination Calls ---------------------------------- */

    pub fn quick_http_request(&mut self, context_id: i32, num_request_headers: i32, num_response_headers: i32) {
        println!("CALL TO:   quick_http_request");
        println!("ARGS:      context_id -> {}, num_request_headers -> {}, num_response_headers -> {}",
        context_id, num_request_headers, num_response_headers);
        self.function_call = FunctionCall::ProxyOnRequestHeaders(context_id, num_request_headers);
        let _ = self.execute_and_expect(Some(0));
        self.function_call = FunctionCall::ProxyOnResponseHeaders(context_id, num_response_headers);
        let _ = self.execute_and_expect(Some(0));
        self.function_call = FunctionCall::ProxyOnLog(context_id);
        let _ = self.execute_and_expect(None);
    }

}


pub trait WasmExpect<'a> {
    type ReturnType;
    fn new(tester: &'a mut Tester) -> Self;
    fn expect(&mut self, return_type: Self::ReturnType);
}


pub struct ExpectNone<'a> {
    tester: &'a mut Tester
}

impl<'a> WasmExpect<'a> for ExpectNone<'a> {
    type ReturnType = Option<()>;
    
    fn new(tester: &'a mut Tester) -> ExpectNone<'a> {
        ExpectNone {
            tester: tester
        }
    }

    fn expect(&mut self, return_type: Self::ReturnType) {

    }
}


pub struct ExpectBool<'a> {
    tester: &'a mut Tester
}

impl<'a> WasmExpect<'a> for ExpectBool<'a> {
    type ReturnType = bool;

    fn new(tester: &'a mut Tester) -> ExpectBool<'a> {
        ExpectBool {
            tester: tester
        }
    }

    fn expect(&mut self, return_type: Self::ReturnType) {

    }
}


pub struct ExpectAction<'a> {
    tester: &'a mut Tester
}

impl<'a> WasmExpect<'a> for ExpectAction<'a> {
    type ReturnType = Action;
    
    fn new(tester: &'a mut Tester) -> ExpectAction<'a> {
        ExpectAction {
            tester: tester
        }
    }
    
    fn expect(&mut self, return_type: Self::ReturnType) {

    }
}

