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
}

pub fn get_abi_version(module: &Module) -> AbiVersion {
    if module.get_export("proxy_abi_version_0_1_0") != None {
        AbiVersion::ProxyAbiVersion0_1_0
    } else if module.get_export("proxy_abi_version_0_2_0") != None {
        AbiVersion::ProxyAbiVersion0_2_0
    } else {
        panic!("test-framework does not support proxy-wasm modules of this abi version");
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
            None => panic!("Failed to acquire \"{}\" from get_hostfunc() in src/hostcalls.rs --> check configuration", import.name())
        }
    }
    (HOST.clone(), EXPECT.clone())
}

fn get_hostfunc(store: &Store, _abi_version: AbiVersion, import: &ImportType) -> Option<Func> {
    match import.name() {
        "proxy_log" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>, level: i32, message_data: i32, message_size: i32| -> i32 {
                    // Default Function: retrieve and display log message from proxy-wasm module
                    // Expectation: ensure the log level and the message data are as expected
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!("=>   Error: proxy_log cannot get_export \"memory\"");
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

                        if let Some(expect_log_string) =
                            EXPECT.lock().unwrap().staged.get_expect_log(level)
                        {
                            assert_eq!(string_msg.to_string(), expect_log_string);
                        }

                        println!(
                            "=>   proxy_log | Level: {} | Message: {}",
                            level, string_msg
                        );
                    }
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_get_current_time_nanoseconds" => {
            Some(Func::wrap(
                &store,
                |caller: Caller<'_>, return_time: i32| -> i32 {
                    // Default Function: respond to proxy-wasm module with the current time
                    // Expectation: respond with a pre-set expected time
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(mem)) => mem,
                        _ => {
                            println!("=>   Error: proxy_get_current_time_nanoseconds cannot get export \"memory\"");
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
                    return Status::Ok as i32;
                },
            ))
        }

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
                    if let Some(tick_period_millis) = EXPECT
                        .lock()
                        .unwrap()
                        .staged
                        .get_expect_set_tick_period_millis()
                    {
                        assert_eq!(tick_period_millis, period as u128);
                    }
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_get_configuration" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, _return_buffer_data: i32, _return_buffer_size: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("-     proxy_get_configuration | ");

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
                            println!(
                                "=>   Error: proxy_get_buffer_bytes cannot get export \"memory\""
                            );
                            return Status::InternalFailure as i32;
                        }
                    };

                    let malloc = match caller.get_export("malloc") {
                        Some(Extern::Func(func)) => func.get1::<i32, i32>().unwrap(),
                        _ => {
                            println!(
                                "=>   Error: proxy_get_buffer_bytes cannot get export \"malloc\""
                            );
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
                            println!(
                                "=>   Error: proxy_set_buffer_bytes cannot get export \"memory\""
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
                    return Status::Ok as i32;
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
                            println!("=>   Error: proxy_get_header_map_pairs cannot get export \"memory\"");
                            return Status::InternalFailure as i32;
                        }
                    };

                    let malloc = match caller.get_export("malloc") {
                        Some(Extern::Func(func)) => func.get1::<i32, i32>().unwrap(),
                        _ => {
                            println!("=>   Error: proxy_get_header_map_pairs cannot get export \"malloc\"");
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
                            println!("=>   Error: proxy_set_header_map_pairs cannot get export \"memory\"");
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

                        if let Some(expect_header_map) = EXPECT
                            .lock()
                            .unwrap()
                            .staged
                            .get_expect_set_header_map_pairs(map_type)
                        {
                            assert_eq!(expect_header_map, header_map_ptr.to_vec())
                        }
                    }
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
                            println!("=>   Error: proxy_get_header_map_value cannot get export \"memory\"");
                            return Status::InternalFailure as i32;
                        }
                    };

                    let malloc = match caller.get_export("malloc") {
                        Some(Extern::Func(func)) => func.get1::<i32, i32>().unwrap(),
                        _ => {
                            println!("=>   Error: proxy_get_header_map_value cannot get export \"malloc\"");
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
                                None => panic!("=>   Error: proxy_get_header_map_value | no header map value for key {}", string_key)}
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
                    }

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
                            println!("=>   Error: proxy_replace_header_map_value cannot get export \"memory\"");
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
                    }

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
                            println!("=>   Error: proxy_remove_header_map_value cannot get export \"memory\"");
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
                    }

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
                            println!("=>   Error: proxy_add_header_map_value cannot get export \"memory\"");
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
                    }

                    return Status::Ok as i32;
                },
            ))
        }

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
                    println!("=>   proxy_get_property | ");
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
                    println!("=>   proxy_set_property | ");
                    return Status::InternalFailure as i32;
                },
            ))
        }

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
                    println!("=>   proxy_get_shared_data | ");
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
                    println!("=>   proxy_set_shared_data | ");
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_register_shared_queue" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, _name_data: i32, _name_size: i32, _return_id: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("=>   proxy_register_shared_queue | ");
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
                    println!("=>   proxy_resolve_shared_queue | ");
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
                    println!("=>   proxy_dequeue_shared_queue |");
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
                    println!("=>   proxy_enqueue_shared_queue | ");
                    return Status::InternalFailure as i32;
                },
            ))
        }

        "proxy_continue_stream" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!("=>   proxy_continue_stream | continuing stream");
                return Status::Ok as i32;
            }))
        }

        "proxy_close_stream" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!("=>   proxy_close_stream | closing stream");
                return Status::Ok as i32;
            }))
        }

        "proxy_continue_request" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!("=>   proxy_continue_request | continuing request");
                return Status::Ok as i32;
            }))
        }

        "proxy_continue_response" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!("=>   proxy_continue_response | continuing reponse");
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
                            println!("=>   Error: proxy_send_local_response cannot get export \"memory\"");
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
                                header_data_ptr.to_vec(),
                                grpc_status,
                            );

                        println!(
                            "=>   proxy_send_local_response | status_code:  {}",
                            status_code
                        );
                        println!(
                            "                               | body_data:    {}",
                            string_body.unwrap_or("None")
                        );
                        println!(
                            "                               | headers_data: {:?}",
                            deserialized_header
                        );
                        println!(
                            "                               | grpc_status:  {}",
                            grpc_status
                        );
                    }
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_clear_route_cache" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!("=>   proxy_clear_route_cache | ");
                return Status::InternalFailure as i32;
            }))
        }

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
                            println!("=>   Error: proxy_http_call cannot get export \"memory\"");
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

                        println!("=>   proxy_http_call | upstream_data:  {}", string_upstream);
                        println!(
                            "                     | headers_data:   {:?}",
                            deserialized_header
                        );
                        println!(
                            "                     | body_data:      {}",
                            string_body.unwrap_or("None")
                        );
                        println!(
                            "                     | trailers_data:  {:?}",
                            deserialized_trailer
                        );
                        println!("                     | timeout:        {:?}", timeout);
                    }
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_set_effective_context" => {
            Some(Func::wrap(
                &store,
                |_caller: Caller<'_>, context_id: i32| -> i32 {
                    // Default Function:
                    // Expectation:
                    println!("=>   proxy_set_effective_context | {}", context_id);
                    return Status::Ok as i32;
                },
            ))
        }

        "proxy_done" => {
            Some(Func::wrap(&store, |_caller: Caller<'_>| -> i32 {
                // Default Function:
                // Expectation:
                println!("=>   proxy_done | ");
                return Status::InternalFailure as i32;
            }))
        }

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
