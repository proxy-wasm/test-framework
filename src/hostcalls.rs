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

use crate::expectations::ExpectHandle;
use crate::host_settings::HostHandle;
use crate::types::*;

use lazy_static::lazy_static;
use more_asserts::*;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use wasmtime::*;

lazy_static! {
    static ref HOST: Arc<Mutex<HostHandle>> = Arc::new(Mutex::new(HostHandle::new()));
    static ref EXPECT: Arc<Mutex<ExpectHandle>> = Arc::new(Mutex::new(ExpectHandle::new()));
    pub static ref STATUS: Arc<Mutex<ExpectStatus>> =
        Arc::new(Mutex::new(ExpectStatus::Unexpected));
}

pub fn set_status(expect_status: ExpectStatus) {
    *STATUS.lock().unwrap() = expect_status;
}

pub fn get_status() -> ExpectStatus {
    let status = *STATUS.lock().unwrap();
    status
}

pub fn get_abi_version(module: &Module) -> AbiVersion {
    if module.get_export("proxy_abi_version_0_1_0") != None {
        AbiVersion::ProxyAbiVersion0_1_0
    } else if module.get_export("proxy_abi_version_0_2_0") != None {
        AbiVersion::ProxyAbiVersion0_2_0
    } else {
        panic!("Error: test-framework does not support proxy-wasm modules of this abi version");
    }
}

pub fn generate_import_list(
    store: &Store,
    module: &Module,
    func_vec: Arc<Mutex<Vec<Extern>>>,
) -> (Arc<Mutex<HostHandle>>, Arc<Mutex<ExpectHandle>>) {
    let abi_version = get_abi_version(module);
    HOST.lock().unwrap().staged.set_abi_version(abi_version);
    let imports = module.imports();
    for import in imports {
        match get_hostfunc(&store, abi_version, &import) {
            Some(func) => (*func_vec).lock().unwrap().push(func.into()),
            None => panic!("Error: failed to acquire \"{}\"", import.name()),
        }
    }
    (HOST.clone(), EXPECT.clone())
}

fn get_hostfunc(store: &Store, _abi_version: AbiVersion, import: &ImportType) -> Option<Func> {
    match import.name() {
        /* ---------------------------------- Configuration and Status ---------------------------------- */
        "proxy_get_configuration" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, _return_buffer_data: i32, _return_buffer_size: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    assert_eq!(
                        HOST.lock().unwrap().staged.get_abi_version(),
                        AbiVersion::ProxyAbiVersion0_1_0
                    );
                    println!(
                        "[vm->host] proxy_get_configuration() -> (...) status: {:?}",
                        get_status()
                    );
                    println!("[vm<-host] proxy_get_configuration() -> (return_buffer_data, return_buffer_size) return: {:?}", Status::InternalFailure);
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_get_status" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _status_code_ptr: i32,
                 _message_ptr: i32,
                 _message_size: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_get_status() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_get_status() -> (..) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        /* ---------------------------------- Logging ---------------------------------- */
        "proxy_log" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>, level: i32, message_data: i32, message_size: i32| -> i32 {
                    // Default Function: retrieve and display log message from proxy-wasm module
                    // Expectation: ensure the log level and the message data are as expected
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!("Error: proxy_log cannot get_export \"memory\"");
                            println!(
                                "[vm<-host] proxy_log(...) return: {:?}",
                                Status::InternalFailure
                            );
                            return Status::InternalFailure as i32;
                        }
                    };

                    unsafe {
                        let data = mem
                            .data_unchecked()
                            .get(message_data as u32 as usize..)
                            .and_then(|arr| arr.get(..message_size as u32 as usize));

                        let string_msg =
                            data.map(|string_msg| std::str::from_utf8(string_msg).unwrap());
                        let string_msg = match string_msg {
                            Some(s) => s,
                            _ => "invalid utf-8 slice",
                        };

                        EXPECT
                            .lock()
                            .unwrap()
                            .staged
                            .get_expect_log(level, string_msg);
                        println!(
                            "[vm->host] proxy_log(level={}, message_data=\"{}\") status: {:?}",
                            level,
                            string_msg,
                            get_status()
                        );
                        // println!("[vm<-host] proxy_log(...) return: {:?}", Status::Ok)
                    }
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_get_log_level" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, _level: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_get_log_level() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_get_log_level() -> (..) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        /* ---------------------------------- Timer ---------------------------------- */
        "proxy_set_tick_period_milliseconds" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, period: i32| -> i32 {
                    // Default Function: receive and store tick period from proxy-wasm module
                    // Expectation: assert received tick period is equal to expected
                    HOST.lock()
                        .unwrap()
                        .staged
                        .set_tick_period_millis(period as u64);
                    EXPECT
                        .lock()
                        .unwrap()
                        .staged
                        .get_expect_set_tick_period_millis(period as u128);

                    println!(
                        "[vm->host] proxy_set_tick_period_milliseconds(period={}) status: {:?}",
                        period,
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_set_tick_period_milliseconds(...) return: {:?}",
                        Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        /* ---------------------------------- Time ---------------------------------- */
        "proxy_get_current_time_nanoseconds" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>, return_time: i32| -> i32 {
                    // Default Function: respond to proxy-wasm module with the current time
                    // Expectation: respond with a pre-set expected time
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!("Error: proxy_get_current_time_nanoseconds cannot get export \"memory\"");
                            println!("[vm<-host] proxy_get_current_time_nanoseconds(...) -> (return_time) return: {:?}", Status::InternalFailure);
                            return Status::InternalFailure as i32;
                        }
                    };

                    let time = match EXPECT
                        .lock()
                        .unwrap()
                        .staged
                        .get_expect_get_current_time_nanos()
                    {
                        Some(current_time_nanos) => current_time_nanos as u64,
                        None => SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_nanos() as u64,
                    };

                    unsafe {
                        let data = mem.data_unchecked_mut().get_unchecked_mut(
                            return_time as u32 as usize..return_time as u32 as usize + 8,
                        );

                        data.copy_from_slice(&time.to_le_bytes());
                    }
                    println!(
                        "[vm->host] proxy_get_current_time_nanoseconds() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_get_current_time_nanoseconds() -> (return_time) return: {:?}",
                        Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        /* ---------------------------------- State Accessors ---------------------------------- */
        "proxy_get_property" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _path_data: i32,
                 _path_size: i32,
                 _return_value_data: i32,
                 _return_value_size: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_get_property(path_data, path_size) -> (...) status: {:?}",
                        get_status()
                    );
                    println!("[vm<-host] proxy_get_property(...) -> (return_value_data, return_value_size) return: {:?}", Status::InternalFailure);
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_set_property" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _path_data: i32,
                 _path_size: i32,
                 _value_data: i32,
                 _value_size: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("[vm->host] proxy_set_property(path_data, path_size, value_data, value_size) status: {:?}", get_status());
                    println!(
                        "[vm<-host] proxy_set_property(...) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        /* ---------------------------------- Continue/Close/Reply/Route ---------------------------------- */
        "proxy_continue_stream" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                assert_eq!(
                    HOST.lock().unwrap().staged.get_abi_version(),
                    AbiVersion::ProxyAbiVersion0_2_0
                );
                println!(
                    "[vm->host] proxy_continue_stream() status: {:?}",
                    get_status()
                );
                println!(
                    "[vm<-host] proxy_continue_stream() return: {:?}",
                    Status::Ok
                );
                assert_ne!(get_status(), ExpectStatus::Failed);
                set_status(ExpectStatus::Unexpected);
                return Status::Ok as i32;
            }))
        }

        "proxy_close_stream" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                assert_eq!(
                    HOST.lock().unwrap().staged.get_abi_version(),
                    AbiVersion::ProxyAbiVersion0_2_0
                );
                println!("[vm->host] proxy_close_stream() status: {:?}", get_status());
                println!("[vm<-host] proxy_close_stream() return: {:?}", Status::Ok);
                assert_ne!(get_status(), ExpectStatus::Failed);
                set_status(ExpectStatus::Unexpected);
                return Status::Ok as i32;
            }))
        }

        "proxy_continue_request" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                assert_eq!(
                    HOST.lock().unwrap().staged.get_abi_version(),
                    AbiVersion::ProxyAbiVersion0_1_0
                );
                println!(
                    "[vm->host] proxy_continue_request() status: {:?}",
                    get_status()
                );
                println!(
                    "[vm<-host] proxy_continue_request() return: {:?}",
                    Status::Ok
                );
                assert_ne!(get_status(), ExpectStatus::Failed);
                set_status(ExpectStatus::Unexpected);
                return Status::Ok as i32;
            }))
        }

        "proxy_continue_response" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                assert_eq!(
                    HOST.lock().unwrap().staged.get_abi_version(),
                    AbiVersion::ProxyAbiVersion0_1_0
                );
                println!(
                    "[vm->host] proxy_continue_response() status: {:?}",
                    get_status()
                );
                println!(
                    "[vm<-host] proxy_continue_response() return: {:?}",
                    Status::Ok
                );
                assert_ne!(get_status(), ExpectStatus::Failed);
                set_status(ExpectStatus::Unexpected);
                return Status::Ok as i32;
            }))
        }

        "proxy_send_local_response" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>,
                 status_code: i32,
                 _status_code_details_data: i32,
                 _status_code_details_size: i32,
                 body_data: i32,
                 body_size: i32,
                 headers_data: i32,
                 headers_size: i32,
                 grpc_status: i32|
                 -> i32 {
                    // Default Function: receive and display local response
                    // Expectation: assert equal the received local response with the expected one
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!(
                                "Error: proxy_send_local_response cannot get export \"memory\""
                            );
                            println!(
                                "[vm<-host] proxy_send_local_response(...) return: {:?}",
                                Status::InternalFailure
                            );
                            return Status::InternalFailure as i32;
                        }
                    };

                    unsafe {
                        let mut string_body: Option<&str> = None;
                        if body_size > 0 {
                            let body_data_ptr = mem
                                .data_unchecked()
                                .get(body_data as u32 as usize..)
                                .and_then(|arr| arr.get(..body_size as u32 as usize));
                            string_body = body_data_ptr
                                .map(|string_msg| std::str::from_utf8(string_msg).unwrap());
                        }

                        let header_data_ptr = mem.data_unchecked().get_unchecked(
                            headers_data as u32 as usize
                                ..headers_data as u32 as usize + headers_size as u32 as usize,
                        );
                        let deserialized_header = serial_utils::deserialize_map(header_data_ptr);

                        EXPECT
                            .lock()
                            .unwrap()
                            .staged
                            .get_expect_send_local_response(
                                status_code,
                                string_body,
                                &header_data_ptr,
                                grpc_status,
                            );

                        println!("[vm->host] proxy_send_local_response(status_code={}, status_code_details_data, status_code_details_size", status_code);
                        println!(
                            "                                     body_data={}, body_size={}",
                            string_body.unwrap_or("None"),
                            body_size
                        );
                        println!("                                     headers_data={:?}, headers_size={}) status: {:?}", deserialized_header, headers_size, get_status());
                    }
                    println!(
                        "[vm<-host] proxy_send_local_response(...) return: {:?}",
                        Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_clear_route_cache" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!(
                    "[vm->host] proxy_clear_route_cache() status: {:?}",
                    get_status()
                );
                println!(
                    "[vm<-host] proxy_clear_route_cache() return: {:?}",
                    Status::InternalFailure
                );
                return Status::InternalFailure as i32;
            }))
        }

        /* ---------------------------------- SharedData ---------------------------------- */
        "proxy_get_shared_data" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _key_data: i32,
                 _key_size: i32,
                 _return_value_data: i32,
                 _return_value_size: i32,
                 _return_cas: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("[vm->host] proxy_get_shared_data(key_data, key_size) -> (...) status: {:?}", get_status());
                    println!("[vm<-host] proxy_get_shared_data(...) -> (return_value_data, return_value_size, return_cas) return: {:?}", Status::InternalFailure);
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_set_shared_data" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _key_data: i32,
                 _key_size: i32,
                 _value_data: i32,
                 _value_size: i32,
                 _cas: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("[vm->host] proxy_set_shared_data(key_data, key_size, value_data, value_size, cas) status: {:?}", get_status());
                    println!(
                        "[vm<-host] proxy_set_shared_data(...) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        /* ---------------------------------- SharedQueue ---------------------------------- */
        "proxy_register_shared_queue" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, _name_data: i32, _name_size: i32, _return_id: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("[vm->host] proxy_register_shared_queue(name_data, name_size) -> (...) status: {:?}", get_status());
                    println!(
                        "[vm<-host] proxy_register_shared_queue(...) -> (return_id) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_resolve_shared_queue" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _vm_id_data: i32,
                 _vm_id_size: i32,
                 _name_data: i32,
                 _name_size: i32,
                 _return_id: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("[vm->host] proxy_resolve_shared_queue(vm_id_data, vm_id_size, name_data, name_size) -> (...) status: {:?}", get_status());
                    println!(
                        "[vm<-host] proxy_resolve_shared_queue(...) -> (return_id) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_dequeue_shared_queue" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _queue_id: i32,
                 _payload_data: i32,
                 _payload_size: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("[vm->host] proxy_dequeue_shared_queue(queue_id, payload_data, payload_size) status: {:?}", get_status());
                    println!(
                        "[vm<-host] proxy_dequeue_shared_queue(...) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_enqueue_shared_queue" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, _queue_id: i32, _value_data: i32, _value_size: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("[vm->host] proxy_enqueue_shared_queue(queue_id, value_data, value_size) status: {:?}", get_status());
                    println!(
                        "[vm<-host] proxy_enqueue_shared_queue(...) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        /* ---------------------------------- Headers/Trailers/Metadata Maps ---------------------------------- */
        "proxy_get_header_map_size" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, _map_type: i32, _map_size: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_get_header_map_size() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_get_header_map_size() -> (..) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_get_header_map_pairs" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>,
                 map_type: i32,
                 return_map_data: i32,
                 return_map_size: i32|
                 -> i32 {
                    // Default Function: respond with default header map pairs depending on map_type
                    // Expectation: respond with set expected header map pairs
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!(
                                "Error: proxy_get_header_map_pairs cannot get export \"memory\""
                            );
                            println!("[vm<-host] proxy_get_header_map_pairs(...) -> (return_map_data, return_map_size) return: {:?}", Status::InternalFailure);
                            return Status::InternalFailure as i32;
                        }
                    };

                    let malloc = match caller.get_export("malloc") {
                        Some(Extern::Func(func)) => func.get1::<i32, i32>().unwrap(),
                        _ => {
                            println!(
                                "Error: proxy_get_header_map_pairs cannot get export \"malloc\""
                            );
                            println!("[vm<-host] proxy_get_header_map_pairs(...) -> (return_map_data, return_map_size) return: {:?}", Status::InternalFailure);
                            return Status::InternalFailure as i32;
                        }
                    };

                    let serial_map = match EXPECT
                        .lock()
                        .unwrap()
                        .staged
                        .get_expect_get_header_map_pairs(map_type)
                    {
                        Some(header_map_pairs) => header_map_pairs,
                        None => HOST.lock().unwrap().staged.get_header_map_pairs(map_type),
                    };
                    let serial_map_size = serial_map.len();

                    unsafe {
                        let return_map_size_ptr = mem.data_unchecked_mut().get_unchecked_mut(
                            return_map_size as u32 as usize..return_map_size as u32 as usize + 4,
                        );

                        let return_map_data_ptr = mem.data_unchecked_mut().get_unchecked_mut(
                            return_map_data as u32 as usize..return_map_data as u32 as usize + 4,
                        );

                        let map_data_add = malloc(serial_map_size as i32).unwrap() as u32 as usize;
                        let map_data_ptr = mem
                            .data_unchecked_mut()
                            .get_unchecked_mut(map_data_add..map_data_add + serial_map_size);
                        map_data_ptr.copy_from_slice(&serial_map);

                        return_map_data_ptr.copy_from_slice(&(map_data_add as u32).to_le_bytes());
                        return_map_size_ptr
                            .copy_from_slice(&(serial_map_size as u32).to_le_bytes());
                    }
                    println!(
                        "[vm->host] proxy_get_header_map_pairs(map_type={}) -> (...) status: {:?}",
                        map_type,
                        get_status()
                    );
                    println!("[vm<-host] proxy_get_header_map_pairs(...) -> (return_map_data, return_map_size) return: {:?}", Status::Ok);
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_set_header_map_pairs" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>, map_type: i32, map_data: i32, map_size: i32| -> i32 {
                    // Default Function: Reads and sets the according header map as the simulator default for the given map type
                    // Expectation: asserts that the received header map and header map type corresponds to the expected one
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!(
                                "[vm<-host] proxy_set_header_map_pairs(...) return: {:?}",
                                Status::InternalFailure
                            );
                            println!(
                                "Error: proxy_set_header_map_pairs cannot get export \"memory\""
                            );
                            return Status::InternalFailure as i32;
                        }
                    };

                    unsafe {
                        let header_map_ptr = mem.data_unchecked().get_unchecked(
                            map_data as u32 as usize..(map_data + map_size) as u32 as usize,
                        );

                        HOST.lock().unwrap().staged.set_header_map_pairs(
                            map_type,
                            serial_utils::deserialize_map(header_map_ptr)
                                .iter()
                                .map(|(k, v)| (k as &str, v as &str))
                                .collect(),
                        );
                        EXPECT
                            .lock()
                            .unwrap()
                            .staged
                            .get_expect_set_header_map_pairs(map_type, header_map_ptr);
                    }
                    println!("[vm->host] proxy_set_header_map_pairs(map_type={}, map_data, map_size) status: {:?}", 
                        map_type, get_status()
                    );
                    println!(
                        "[vm<-host] proxy_set_header_map_pairs(...) return: {:?}",
                        Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_get_header_map_value" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>,
                 map_type: i32,
                 key_data: i32,
                 key_size: i32,
                 return_value_data: i32,
                 return_value_size: i32|
                 -> i32 {
                    // Default Function: respond with a default header map value corresponding to map_type (if exists)
                    // Expectation: respond with set expected header map value for the given key and map_type
                    // Panics if there is no header map value in expectation or host simulator for the provided map_type and key
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!(
                                "Error: proxy_get_header_map_value cannot get export \"memory\""
                            );
                            println!("[vm<-host] proxy_get_header_map_value(...) -> (return_value_data, return_value_size) return: {:?}", Status::InternalFailure);
                            return Status::InternalFailure as i32;
                        }
                    };

                    let malloc = match caller.get_export("malloc") {
                        Some(Extern::Func(func)) => func.get1::<i32, i32>().unwrap(),
                        _ => {
                            println!(
                                "Error: proxy_get_header_map_value cannot get export \"malloc\""
                            );
                            println!("[vm<-host] proxy_get_header_map_value(...) -> (return_value_data, return_value_size) return: {:?}", Status::InternalFailure);
                            return Status::InternalFailure as i32;
                        }
                    };

                    unsafe {
                        let key_data_ptr = mem
                            .data_unchecked()
                            .get(key_data as u32 as usize..)
                            .and_then(|arr| arr.get(..key_size as u32 as usize));
                        let string_key = key_data_ptr
                            .map(|string_msg| std::str::from_utf8(string_msg).unwrap())
                            .unwrap();

                        let string_value = match EXPECT
                            .lock()
                            .unwrap()
                            .staged
                            .get_expect_get_header_map_value(map_type, string_key)
                        {
                            Some(expect_string_value) => expect_string_value,
                            None => {
                                match HOST.lock().unwrap().staged.get_header_map_value(map_type, &string_key) {
                                Some(host_string_value) => host_string_value,
                                None => panic!("Error: proxy_get_header_map_value | no header map value for key {}", string_key)}
                            }
                        };

                        let value_data_add =
                            malloc(string_value.len() as i32).unwrap() as u32 as usize;
                        let value_data_ptr = mem
                            .data_unchecked_mut()
                            .get_unchecked_mut(value_data_add..value_data_add + string_value.len());
                        value_data_ptr.copy_from_slice((&string_value).as_bytes());

                        let return_value_data_ptr = mem.data_unchecked_mut().get_unchecked_mut(
                            return_value_data as u32 as usize
                                ..return_value_data as u32 as usize + 4,
                        );

                        let return_value_size_ptr = mem.data_unchecked_mut().get_unchecked_mut(
                            return_value_size as u32 as usize
                                ..return_value_size as u32 as usize + 4,
                        );

                        return_value_data_ptr
                            .copy_from_slice(&(value_data_add as u32).to_le_bytes());
                        return_value_size_ptr
                            .copy_from_slice(&(string_value.len() as u32).to_le_bytes());

                        println!("[vm->host] proxy_get_header_map_value(map_type={}, key_data={}, key_size={}) -> (...) status: {:?}", 
                            map_type, string_key, key_size, get_status()
                        );
                        println!("[vm<-host] proxy_get_header_map_value(...) -> (return_value_data={}, return_value_size={}) return: {:?}", 
                            string_value, string_value.len(), Status::Ok
                        );
                    }
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_replace_header_map_value" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>,
                 map_type: i32,
                 key_data: i32,
                 key_size: i32,
                 value_data: i32,
                 value_size: i32|
                 -> i32 {
                    // Default Function: replace the specified key-value pair in the default host environment if it exists
                    // Expectation: assert that the received key-value pair are as expected
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!("Error: proxy_replace_header_map_value cannot get export \"memory\"");
                            println!(
                                "[vm<-host] proxy_replace_header_map_value(...) return: {:?}",
                                Status::InternalFailure
                            );
                            return Status::InternalFailure as i32;
                        }
                    };

                    unsafe {
                        let key_data_ptr = mem
                            .data_unchecked()
                            .get(key_data as u32 as usize..)
                            .and_then(|arr| arr.get(..key_size as u32 as usize));
                        let string_key = key_data_ptr
                            .map(|string_msg| std::str::from_utf8(string_msg).unwrap())
                            .unwrap();

                        let value_data_ptr = mem
                            .data_unchecked()
                            .get(value_data as u32 as usize..)
                            .and_then(|arr| arr.get(..value_size as u32 as usize));
                        let string_value = value_data_ptr
                            .map(|string_msg| std::str::from_utf8(string_msg).unwrap())
                            .unwrap();

                        EXPECT
                            .lock()
                            .unwrap()
                            .staged
                            .get_expect_replace_header_map_value(
                                map_type,
                                string_key,
                                string_value,
                            );
                        HOST.lock().unwrap().staged.replace_header_map_value(
                            map_type,
                            string_key,
                            string_value,
                        );
                        println!("[vm->host] proxy_replace_header_map_value(map_type={}, key_data={}, key_size={}, value_data={}, value_size={}) status: {:?}", 
                            map_type, string_key, string_key.len(), string_value, string_value.len(), get_status()
                        );
                    }
                    println!(
                        "[vm<-host] proxy_replace_header_map_value(...) return: {:?}",
                        Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_remove_header_map_value" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>, map_type: i32, key_data: i32, key_size: i32| -> i32 {
                    // Default Function: remove the specified key-value pair in the default host environment if it exists
                    // Expectation: assert that the received key is as expected
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!(
                                "Error: proxy_remove_header_map_value cannot get export \"memory\""
                            );
                            println!(
                                "[vm<-host] proxy_remove_header_map_value(...) return: {:?}",
                                Status::InternalFailure
                            );
                            return Status::InternalFailure as i32;
                        }
                    };

                    unsafe {
                        let key_data_ptr = mem
                            .data_unchecked()
                            .get(key_data as u32 as usize..)
                            .and_then(|arr| arr.get(..key_size as u32 as usize));
                        let string_key = key_data_ptr
                            .map(|string_msg| std::str::from_utf8(string_msg).unwrap())
                            .unwrap();

                        EXPECT
                            .lock()
                            .unwrap()
                            .staged
                            .get_expect_remove_header_map_value(map_type, string_key);
                        HOST.lock()
                            .unwrap()
                            .staged
                            .remove_header_map_value(map_type, string_key);
                        println!("[vm->host] proxy_remove_header_map_value(map_type={}, key_data={}, key_size={}) status: {:?}", 
                            map_type, string_key, string_key.len(), get_status()
                        );
                    }
                    println!(
                        "[vm<-host] proxy_remove_header_map_value(...) return: {:?}",
                        Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_add_header_map_value" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>,
                 map_type: i32,
                 key_data: i32,
                 key_size: i32,
                 value_data: i32,
                 value_size: i32|
                 -> i32 {
                    // Default Function: add the specified key-value pair in the default host environment if it exists
                    // Expectation: assert that the received key-value pair are as expected
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!(
                                "Error: proxy_add_header_map_value cannot get export \"memory\""
                            );
                            println!(
                                "[vm<-host] proxy_add_header_map_value(...) return: {:?}",
                                Status::InternalFailure
                            );
                            return Status::InternalFailure as i32;
                        }
                    };

                    unsafe {
                        let key_data_ptr = mem
                            .data_unchecked()
                            .get(key_data as u32 as usize..)
                            .and_then(|arr| arr.get(..key_size as u32 as usize));
                        let string_key = key_data_ptr
                            .map(|string_msg| std::str::from_utf8(string_msg).unwrap())
                            .unwrap();

                        let value_data_ptr = mem
                            .data_unchecked()
                            .get(value_data as u32 as usize..)
                            .and_then(|arr| arr.get(..value_size as u32 as usize));
                        let string_value = value_data_ptr
                            .map(|string_msg| std::str::from_utf8(string_msg).unwrap())
                            .unwrap();

                        EXPECT
                            .lock()
                            .unwrap()
                            .staged
                            .get_expect_add_header_map_value(map_type, string_key, string_value);
                        HOST.lock().unwrap().staged.add_header_map_value(
                            map_type,
                            string_key,
                            string_value,
                        );
                        println!("[vm->host] proxy_add_header_map_value(map_type={}, key_data={}, key_size={}, value_data={}, value_size={}) status: {:?}", 
                            map_type, string_key, string_key.len(), string_value, string_value.len(), get_status()
                        );
                    }
                    println!(
                        "[vm<-host] proxy_add_header_map_value(...) return: {:?}",
                        Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        /* ---------------------------------- Buffer ---------------------------------- */
        "proxy_get_buffer_status" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _buffer_type: i32,
                 _length_ptr: i32,
                 _flags_ptr: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_get_buffer_status() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_get_buffer_status() -> (..) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_get_buffer_bytes" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>,
                 buffer_type: i32,
                 start: i32,
                 max_size: i32,
                 return_buffer_data: i32,
                 return_buffer_size: i32|
                 -> i32 {
                    // Default Function: generate and return random buffer_bytes of length max_size - start
                    // Expectation: return buffer bytes set in expectation
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!("Error: proxy_get_buffer_bytes cannot get export \"memory\"");
                            println!("[vm<-host] proxy_get_buffer_bytes(...) -> (return_buffer_data, return_buffer_size) return: {:?}", Status::InternalFailure);
                            return Status::InternalFailure as i32;
                        }
                    };

                    let malloc = match caller.get_export("malloc") {
                        Some(Extern::Func(func)) => func.get1::<i32, i32>().unwrap(),
                        _ => {
                            println!("Error: proxy_get_buffer_bytes cannot get export \"malloc\"");
                            println!("[vm<-host] proxy_get_buffer_bytes(...) -> (return_buffer_data, return_buffer_size) return: {:?}", Status::InternalFailure);
                            return Status::InternalFailure as i32;
                        }
                    };

                    let response_body = match EXPECT
                        .lock()
                        .unwrap()
                        .staged
                        .get_expect_get_buffer_bytes(buffer_type)
                    {
                        Some(expect_buffer_bytes) => {
                            assert_le!(expect_buffer_bytes.len(), (max_size - start) as usize);
                            expect_buffer_bytes
                        }
                        None => {
                            let buffer_bytes: Bytes;
                            let host_buffer_bytes =
                                HOST.lock().unwrap().staged.get_buffer_bytes(buffer_type);
                            if host_buffer_bytes.len() == (max_size - start) as usize {
                                buffer_bytes = host_buffer_bytes;
                            } else {
                                buffer_bytes = serial_utils::generate_random_string(
                                    (max_size - start) as usize,
                                )
                                .as_bytes()
                                .to_vec();
                            }
                            buffer_bytes
                        }
                    };

                    unsafe {
                        let return_buffer_size_ptr = mem.data_unchecked_mut().get_unchecked_mut(
                            return_buffer_size as u32 as usize
                                ..return_buffer_size as u32 as usize + 4,
                        );

                        let return_buffer_data_ptr = mem.data_unchecked_mut().get_unchecked_mut(
                            return_buffer_data as u32 as usize
                                ..return_buffer_data as u32 as usize + 4,
                        );

                        // allocate memory and store buffer bytes
                        let buffer_data_add =
                            malloc(response_body.len() as i32).unwrap() as u32 as usize;
                        let buffer_data_ptr = mem.data_unchecked_mut().get_unchecked_mut(
                            buffer_data_add..buffer_data_add + response_body.len(),
                        );
                        buffer_data_ptr.copy_from_slice(&response_body);

                        return_buffer_size_ptr
                            .copy_from_slice(&(response_body.len() as u32).to_le_bytes());
                        return_buffer_data_ptr
                            .copy_from_slice(&(buffer_data_add as u32).to_le_bytes());
                    }
                    println!(
                        "[vm->host] proxy_get_buffer_bytes(buffer_type={}, start={}, max_size={}) -> (...) status: {:?}",
                        buffer_type, start, max_size, get_status()
                    );
                    println!(
                        "[vm<-host] proxy_get_buffer_bytes(...) -> (return_buffer_data, return_buffer_size) return: {:?}", Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_set_buffer_bytes" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>,
                 buffer_type: i32,
                 start: i32,
                 size: i32,
                 buffer_data: i32,
                 buffer_size: i32|
                 -> i32 {
                    // Default Function: set received buffer data as default
                    // Expectation: assert that the received buffer bytes is as expected
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!("Error: proxy_set_buffer_bytes cannot get export \"memory\"");
                            println!(
                                "[vm<-host] proxy_set_buffer_bytes(...) return: {:?}",
                                Status::InternalFailure
                            );
                            return Status::InternalFailure as i32;
                        }
                    };

                    unsafe {
                        let buffer_data_ptr = mem.data_unchecked().get_unchecked(
                            buffer_data as u32 as usize
                                ..(buffer_data + buffer_size) as u32 as usize,
                        );
                        assert_ge!(buffer_data_ptr.len(), (start + size) as usize);

                        EXPECT.lock().unwrap().staged.get_expect_set_buffer_bytes(
                            buffer_type,
                            &buffer_data_ptr[start as usize..(start + size) as usize],
                        );
                        HOST.lock().unwrap().staged.set_buffer_bytes(
                            buffer_type,
                            std::str::from_utf8(
                                &buffer_data_ptr[start as usize..(start + size) as usize],
                            )
                            .unwrap(),
                        );
                    }
                    println!(
                        "[vm<-host] proxy_set_buffer_bytes(buffer_type={},
                            start={},
                            size={},
                            buffer_data,
                            buffer_size) status: {:?}",
                        buffer_type,
                        start,
                        size,
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_set_buffer_bytes(...) return: {:?}",
                        Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        /* ---------------------------------- HTTP ---------------------------------- */
        "proxy_http_call" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>,
                 upstream_data: i32,
                 upstream_size: i32,
                 headers_data: i32,
                 headers_size: i32,
                 body_data: i32,
                 body_size: i32,
                 trailers_data: i32,
                 trailers_size: i32,
                 timeout: i32,
                 return_token: i32|
                 -> i32 {
                    // Default Function: receives and displays http call from proxy-wasm module
                    // Expectation: asserts equal the receieved http call with the expected one
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!("Error: proxy_http_call cannot get export \"memory\"");
                            println!(
                                "[vm<-host] proxy_http_call(...) -> (return_token) return: {:?}",
                                Status::InternalFailure
                            );
                            return Status::InternalFailure as i32;
                        }
                    };

                    // expectation description not implemented yet
                    unsafe {
                        let upstream_data_ptr = mem
                            .data_unchecked()
                            .get(upstream_data as u32 as usize..)
                            .and_then(|arr| arr.get(..upstream_size as u32 as usize));
                        let string_upstream = upstream_data_ptr
                            .map(|string_msg| std::str::from_utf8(string_msg).unwrap())
                            .unwrap();

                        let mut string_body: Option<&str> = None;
                        if body_size > 0 {
                            let body_data_ptr = mem
                                .data_unchecked()
                                .get(body_data as u32 as usize..)
                                .and_then(|arr| arr.get(..body_size as u32 as usize));
                            string_body = body_data_ptr
                                .map(|string_msg| std::str::from_utf8(string_msg).unwrap());
                        }

                        let header_data_ptr = mem.data_unchecked().get_unchecked(
                            headers_data as u32 as usize
                                ..headers_data as u32 as usize + headers_size as u32 as usize,
                        );
                        let deserialized_header = serial_utils::deserialize_map(header_data_ptr);

                        let trailer_data_ptr = mem.data_unchecked().get_unchecked(
                            trailers_data as u32 as usize
                                ..trailers_data as u32 as usize + trailers_size as u32 as usize,
                        );
                        let deserialized_trailer = serial_utils::deserialize_map(trailer_data_ptr);

                        let token_id = match EXPECT.lock().unwrap().staged.get_expect_http_call(
                            string_upstream,
                            header_data_ptr,
                            string_body,
                            trailer_data_ptr,
                            timeout,
                        ) {
                            Some(expect_token) => expect_token,
                            None => 0,
                        };

                        let return_token_add = mem.data_unchecked_mut().get_unchecked_mut(
                            return_token as u32 as usize..return_token as u32 as usize + 4,
                        );
                        return_token_add.copy_from_slice(&token_id.to_le_bytes());
                        println!(
                            "[vm->host] proxy_http_call(upstream_data={:?}, upstream_size={}",
                            string_upstream,
                            string_upstream.len()
                        );
                        println!(
                            "                           headers_data={:?}, headers_size={}",
                            deserialized_header, headers_size
                        );
                        println!(
                            "                           body_data={}, body_size={}",
                            string_body.unwrap_or("None"),
                            string_body.map_or(0, |data| data.len())
                        );
                        println!(
                            "                           trailers_data={:?}, trailers_size={}",
                            deserialized_trailer, trailers_size
                        );
                        println!(
                            "                           timeout) -> (...) status: {:?}",
                            get_status()
                        );
                        println!(
                            "[vm<-host] proxy_http_call(...) -> (return_token={}) return: {:?}",
                            token_id,
                            Status::Ok
                        );
                    }
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        /* ---------------------------------- gRPC ---------------------------------- */
        "proxy_grpc_call" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _service_ptr: i32,
                 _service_size: i32,
                 _service_name_ptr: i32,
                 _service_name_size: i32,
                 _method_name_ptr: i32,
                 _method_name_size: i32,
                 _initial_metadata_ptr: i32,
                 _initial_metadata_size: i32,
                 _request_ptr: i32,
                 _request_size: i32,
                 _timeout_milliseconds: i32,
                 _token_ptr: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_grpc_call() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_grpc_call() -> (..) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_grpc_stream" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _service_ptr: i32,
                 _service_size: i32,
                 _service_name_ptr: i32,
                 _service_name_size: i32,
                 _method_name_ptr: i32,
                 _method_name_size: i32,
                 _initial_metadata: i32,
                 _initial_metadata_size: i32,
                 _token_ptr: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_grpc_stream() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_grpc_stream() -> (..) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_grpc_cancel" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, _token: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_grpc_cancel() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_grpc_cancel() -> (..) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_grpc_close" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, _token: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_grpc_close() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_grpc_close() -> (..) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_grpc_send" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>,
                 _token: i32,
                 _message_ptr: i32,
                 _message_size: i32,
                 _end_of_stream: i32|
                 -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_grpc_send() -> (...) status: {:?}",
                        get_status()
                    );
                    println!(
                        "[vm<-host] proxy_grpc_send() -> (..) return: {:?}",
                        Status::InternalFailure
                    );
                    return Status::InternalFailure as i32;
                },
            ))
        }

        /* ---------------------------------- Metrics ---------------------------------- */
        "proxy_define_metric" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!(
                    "[vm->host] proxy_define_metric() -> (...) status: {:?}",
                    get_status()
                );
                println!(
                    "[vm<-host] proxy_define_metric() -> (..) return: {:?}",
                    Status::InternalFailure
                );
                return Status::InternalFailure as i32;
            }))
        }

        "proxy_increment_metric" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!(
                    "[vm->host] proxy_increment_metric() -> (...) status: {:?}",
                    get_status()
                );
                println!(
                    "[vm<-host] proxy_increment_metric() -> (..) return: {:?}",
                    Status::InternalFailure
                );
                return Status::InternalFailure as i32;
            }))
        }

        "proxy_record_metric" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!(
                    "[vm->host] proxy_record_metric() -> (...) status: {:?}",
                    get_status()
                );
                println!(
                    "[vm<-host] proxy_record_metric() -> (..) return: {:?}",
                    Status::InternalFailure
                );
                return Status::InternalFailure as i32;
            }))
        }

        "proxy_get_metric" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!(
                    "[vm->host] proxy_get_metric() -> (...) status: {:?}",
                    get_status()
                );
                println!(
                    "[vm<-host] proxy_get_metric() -> (..) return: {:?}",
                    Status::InternalFailure
                );
                return Status::InternalFailure as i32;
            }))
        }

        /* ---------------------------------- System ---------------------------------- */
        "proxy_set_effective_context" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, context_id: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!(
                        "[vm->host] proxy_set_effective_context(context_id={}) status: {:?}",
                        context_id,
                        get_status()
                    );
                    println!(
                        "[vm->host] proxy_set_effective_context(...) return: {:?}",
                        Status::Ok
                    );
                    assert_ne!(get_status(), ExpectStatus::Failed);
                    set_status(ExpectStatus::Unexpected);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_done" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!("[vm->host] proxy_done() status: {:?}", get_status());
                println!(
                    "[vm->host] proxy_done() return: {:?}",
                    Status::InternalFailure
                );
                return Status::InternalFailure as i32;
            }))
        }

        "proxy_call_foreign_function" => Some(Func::wrap(
            &store,
            |_caller: Caller<'_>,
             _function_name: i32,
             _function_name_size: i32,
             _arguments: i32,
             _arguments_size: i32,
             _results: i32,
             _size_t: i32|
             -> i32 {
                println!(
                    "[vm->host] proxy_call_foreign_function() status: {:?}",
                    get_status()
                );
                println!(
                    "[vm->host] proxy_call_foreign_function() return: {:?}",
                    Status::InternalFailure
                );
                return Status::InternalFailure as i32;
            },
        )),

        _ => None,
    }
}

pub mod serial_utils {

    type Bytes = Vec<u8>;
    use rand::Rng;
    use std::convert::TryFrom;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";

    pub fn _serialize_property_path(path: Vec<&str>) -> Bytes {
        if path.is_empty() {
            return Vec::new();
        }
        let mut size: usize = 0;
        for part in &path {
            size += part.len() + 1;
        }
        let mut bytes: Bytes = Vec::with_capacity(size);
        for part in &path {
            bytes.extend_from_slice(&part.as_bytes());
            bytes.push(0);
        }
        bytes.pop();
        bytes
    }

    pub fn serialize_map(map: Vec<(&str, &str)>) -> Bytes {
        let mut size: usize = 4;
        for (name, value) in &map {
            size += name.len() + value.len() + 10;
        }
        let mut bytes: Bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (name, value) in &map {
            bytes.extend_from_slice(&(name.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        }
        for (name, value) in &map {
            bytes.extend_from_slice(&name.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&value.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    pub fn deserialize_map(bytes: &[u8]) -> Vec<(String, String)> {
        let mut map = Vec::new();
        if bytes.is_empty() {
            return map;
        }
        let size = u32::from_le_bytes(<[u8; 4]>::try_from(&bytes[0..4]).unwrap()) as usize;
        let mut p = 4 + size * 8;
        for n in 0..size {
            let s = 4 + n * 8;
            let size = u32::from_le_bytes(<[u8; 4]>::try_from(&bytes[s..s + 4]).unwrap()) as usize;
            let key = bytes[p..p + size].to_vec();
            p += size + 1;
            let size =
                u32::from_le_bytes(<[u8; 4]>::try_from(&bytes[s + 4..s + 8]).unwrap()) as usize;
            let value = bytes[p..p + size].to_vec();
            p += size + 1;
            map.push((
                String::from_utf8(key).unwrap(),
                String::from_utf8(value).unwrap(),
            ));
        }
        map
    }

    pub fn generate_random_string(string_len: usize) -> String {
        let mut rng = rand::thread_rng();
        let random_string: String = (0..string_len)
            .map(|_| {
                let idx = rng.gen_range(0, CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        random_string
    }
}
