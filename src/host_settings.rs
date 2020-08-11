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

use crate::hostcalls::serial_utils::serialize_map;
use crate::types::*;

use std::collections::HashMap;
use std::time::Duration;

// Global structure for handling default host behaviour (and high-level expectation setting)
pub struct HostHandle {
    pub staged: HostSettings,
}

impl HostHandle {
    pub fn new() -> HostHandle {
        HostHandle {
            staged: HostSettings::new(AbiVersion::None),
        }
    }

    pub fn reset(&mut self, abi_version: AbiVersion) {
        self.staged = HostSettings::new(abi_version);
    }

    pub fn print_staged(&self) {
        println!("{:?}", self.staged);
    }
}

// Global struct for host environment default settings
#[derive(Debug)]
pub struct HostSettings {
    abi_version: AbiVersion,
    tick_period_millis: Duration,
    header_map_pairs: HashMap<i32, HashMap<String, String>>,
    buffer_bytes: HashMap<i32, Bytes>,
}

impl HostSettings {
    pub fn new(abi_version: AbiVersion) -> HostSettings {
        HostSettings {
            abi_version: abi_version,
            tick_period_millis: Duration::new(0, 0),
            header_map_pairs: default_header_map_pairs(),
            buffer_bytes: default_buffer_bytes(),
        }
    }

    pub fn set_abi_version(&mut self, abi_version: AbiVersion) {
        self.abi_version = abi_version;
    }

    pub fn get_abi_version(&mut self) -> AbiVersion {
        self.abi_version
    }

    pub fn reset_tick_period_millis(&mut self) {
        self.tick_period_millis = Duration::from_millis(0u64);
    }

    pub fn set_tick_period_millis(&mut self, tick_period_millis: u64) {
        self.tick_period_millis = Duration::from_millis(tick_period_millis);
    }

    pub fn get_tick_period_millis(&self) -> u128 {
        self.tick_period_millis.as_millis()
    }

    pub fn reset_buffer_bytes(&mut self) {
        self.buffer_bytes = default_buffer_bytes();
    }

    pub fn set_buffer_bytes(&mut self, buffer_type: i32, buffer_data: &str) {
        self.buffer_bytes
            .insert(buffer_type, buffer_data.as_bytes().to_vec());
    }

    pub fn get_buffer_bytes(&self, buffer_type: i32) -> Bytes {
        let buffer_data = self.buffer_bytes.get(&buffer_type).unwrap().clone();
        buffer_data
    }

    pub fn reset_header_map_pairs(&mut self) {
        self.header_map_pairs = default_header_map_pairs();
    }

    pub fn set_header_map_pairs(&mut self, map_type: i32, header_map_pairs: Vec<(&str, &str)>) {
        let mut header_map = HashMap::new();
        for (header_map_key, header_map_value) in header_map_pairs.into_iter() {
            header_map.insert(header_map_key.to_string(), header_map_value.to_string());
        }
        self.header_map_pairs.insert(map_type, header_map);
    }

    pub fn get_header_map_pairs(&self, map_type: i32) -> Bytes {
        let header_map_pairs = self.header_map_pairs.get(&map_type).unwrap();
        let header_map_pairs = header_map_pairs
            .iter()
            .map(|(k, v)| (k as &str, v as &str))
            .collect();
        serialize_map(header_map_pairs)
    }

    pub fn get_header_map_value(&self, map_type: i32, header_map_key: &str) -> Option<String> {
        let header_map = self.header_map_pairs.get(&map_type).unwrap();
        let header_map_value = header_map.get(header_map_key);
        header_map_value.map(|str_val| str_val.to_string())
    }

    pub fn replace_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        let header_map = self.header_map_pairs.get_mut(&map_type).unwrap();
        header_map.insert(header_map_key.to_string(), header_map_value.to_string());
    }

    pub fn remove_header_map_value(&mut self, map_type: i32, header_map_key: &str) {
        let header_map = self.header_map_pairs.get_mut(&map_type).unwrap();
        header_map.remove(header_map_key);
    }

    pub fn add_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        let header_map = self.header_map_pairs.get_mut(&map_type).unwrap();
        header_map.insert(header_map_key.to_string(), header_map_value.to_string());
    }
}

// functions to retrieve default values
pub fn default_header_map_pairs() -> HashMap<i32, HashMap<String, String>> {
    let mut default_header_maps = HashMap::new();

    let mut http_on_request_headers = HashMap::new();
    http_on_request_headers.insert(":method".to_string(), "GET".to_string());
    http_on_request_headers.insert(
        ":path".to_string(),
        "/default/request/headers/path".to_string(),
    );
    http_on_request_headers.insert(":authority".to_string(), "abi_test_harness".to_string());
    default_header_maps.insert(MapType::HttpRequestHeaders as i32, http_on_request_headers);

    let mut http_on_request_trailers = HashMap::new();
    http_on_request_trailers.insert(":method".to_string(), "GET".to_string());
    http_on_request_trailers.insert(
        ":path".to_string(),
        "/default/request/trailers/path".to_string(),
    );
    http_on_request_trailers.insert(":authority".to_string(), "abi_test_harness".to_string());
    default_header_maps.insert(
        MapType::HttpRequestTrailers as i32,
        http_on_request_trailers,
    );

    let mut http_on_response_headers = HashMap::new();
    http_on_response_headers.insert(":method".to_string(), "GET".to_string());
    http_on_response_headers.insert(
        ":path".to_string(),
        "/default/response/headers/path".to_string(),
    );
    http_on_response_headers.insert(":authority".to_string(), "abi_test_harness".to_string());
    default_header_maps.insert(
        MapType::HttpResponseHeaders as i32,
        http_on_response_headers,
    );

    let mut http_on_response_trailers = HashMap::new();
    http_on_response_trailers.insert(":method".to_string(), "GET".to_string());
    http_on_response_trailers.insert(
        ":path".to_string(),
        "/default/response/trailers/path".to_string(),
    );
    http_on_response_trailers.insert(":authority".to_string(), "abi_test_harness".to_string());
    default_header_maps.insert(
        MapType::HttpResponseTrailers as i32,
        http_on_response_trailers,
    );

    let mut http_call_response_headers = HashMap::new();
    http_call_response_headers.insert(":method".to_string(), "GET".to_string());
    http_call_response_headers.insert(
        ":path".to_string(),
        "/default/call/response/headers/path".to_string(),
    );
    http_call_response_headers.insert(":authority".to_string(), "abi_test_harness".to_string());
    default_header_maps.insert(
        MapType::HttpCallResponseHeaders as i32,
        http_call_response_headers,
    );

    let mut http_call_response_trailers = HashMap::new();
    http_call_response_trailers.insert(":method".to_string(), "GET".to_string());
    http_call_response_trailers.insert(
        ":path".to_string(),
        "/default/call/response/trailers/path".to_string(),
    );
    http_call_response_trailers.insert(":authority".to_string(), "abi_test_harness".to_string());
    default_header_maps.insert(
        MapType::HttpCallResponseTrailers as i32,
        http_call_response_trailers,
    );

    default_header_maps
}

pub fn default_buffer_bytes() -> HashMap<i32, Bytes> {
    let mut default_bytes = HashMap::new();
    default_bytes.insert(
        BufferType::HttpRequestBody as i32,
        "default_http_request_body".as_bytes().to_vec(),
    );
    default_bytes.insert(
        BufferType::HttpResponseBody as i32,
        "default_http_response_body".as_bytes().to_vec(),
    );
    default_bytes.insert(
        BufferType::DownstreamData as i32,
        "default_downstream_data".as_bytes().to_vec(),
    );
    default_bytes.insert(
        BufferType::UpstreamData as i32,
        "default_upstream_data".as_bytes().to_vec(),
    );
    default_bytes.insert(
        BufferType::HttpCallResponseBody as i32,
        "default_call_response_body".as_bytes().to_vec(),
    );
    default_bytes
}
