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
            staged: HostSettings::new(AbiVersion::UnknownAbiVersion, false),
        }
    }

    pub fn reset(&mut self, abi_version: AbiVersion, quiet: bool) {
        self.staged = HostSettings::new(abi_version, quiet);
    }

    pub fn print_staged(&self) {
        println!("{:?}", self.staged);
    }
}

// Global struct for host environment default settings
#[derive(Debug)]
pub struct HostSettings {
    abi_version: AbiVersion,
    quiet: bool,
    effective_context_id: i32,
    tick_period_millis: Duration,
    header_map_pairs: HashMap<i32, Vec<(String, String)>>,
    buffer_bytes: HashMap<i32, Bytes>,
}

impl HostSettings {
    pub fn new(abi_version: AbiVersion, quiet: bool) -> HostSettings {
        HostSettings {
            abi_version: abi_version,
            quiet: quiet,
            effective_context_id: -1,
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

    pub fn set_quiet_mode(&mut self, quiet: bool) {
        self.quiet = quiet;
    }

    pub fn get_quiet_mode(&mut self) -> bool {
        self.quiet
    }

    pub fn set_effective_context(&mut self, effective_context_id: i32) {
        self.effective_context_id = effective_context_id;
    }

    pub fn get_effective_context(&mut self) -> i32 {
        self.effective_context_id
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
        let mut header_map = Vec::new();
        for (header_map_key, header_map_value) in header_map_pairs.into_iter() {
            header_map.push((header_map_key.to_string(), header_map_value.to_string()));
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
        let mut header_map_value: Option<String> = None;
        let header_map = self.header_map_pairs.get(&map_type).unwrap();
        for (key, value) in header_map {
            if key == header_map_key {
                header_map_value = Some(value.to_string());
            }
        }
        header_map_value
    }

    pub fn replace_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        let mut new_header_map: Vec<(String, String)> = Vec::new();
        let header_map = self.header_map_pairs.get(&map_type).unwrap();
        for (key, value) in header_map {
            if key != header_map_key {
                new_header_map.push((key.to_string(), value.to_string()));
            } else {
                new_header_map.push((key.to_string(), header_map_value.to_string()));
            }
        }
        self.header_map_pairs.insert(map_type, new_header_map);
    }

    pub fn remove_header_map_value(&mut self, map_type: i32, header_map_key: &str) {
        let mut new_header_map: Vec<(String, String)> = Vec::new();
        let header_map = self.header_map_pairs.get(&map_type).unwrap();
        for (key, value) in header_map {
            if key != header_map_key {
                new_header_map.push((key.to_string(), value.to_string()));
            }
        }
        self.header_map_pairs.insert(map_type, new_header_map);
    }

    pub fn add_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        let mut key_found = false;
        let mut new_header_map: Vec<(String, String)> = Vec::new();
        let header_map = self.header_map_pairs.get(&map_type).unwrap();
        for (key, value) in header_map {
            if key != header_map_key {
                new_header_map.push((key.to_string(), value.to_string()));
            } else {
                key_found = true;
            }
        }
        if !key_found {
            new_header_map.push((header_map_key.to_string(), header_map_value.to_string()));
        }
        self.header_map_pairs.insert(map_type, new_header_map);
    }
}

// functions to retrieve default values
pub fn default_header_map_pairs() -> HashMap<i32, Vec<(String, String)>> {
    let mut default_header_maps = HashMap::new();

    let mut http_on_request_headers = Vec::new();
    http_on_request_headers.push((":method".to_string(), "GET".to_string()));
    http_on_request_headers.push((
        ":path".to_string(),
        "/default/request/headers/path".to_string(),
    ));
    http_on_request_headers.push((":authority".to_string(), "abi_test_harness".to_string()));
    default_header_maps.insert(MapType::HttpRequestHeaders as i32, http_on_request_headers);

    let mut http_on_request_trailers = Vec::new();
    http_on_request_trailers.push((":method".to_string(), "GET".to_string()));
    http_on_request_trailers.push((
        ":path".to_string(),
        "/default/request/trailers/path".to_string(),
    ));
    http_on_request_trailers.push((":authority".to_string(), "abi_test_harness".to_string()));
    default_header_maps.insert(
        MapType::HttpRequestTrailers as i32,
        http_on_request_trailers,
    );

    let mut http_on_response_headers = Vec::new();
    http_on_response_headers.push((":method".to_string(), "GET".to_string()));
    http_on_response_headers.push((
        ":path".to_string(),
        "/default/response/headers/path".to_string(),
    ));
    http_on_response_headers.push((":authority".to_string(), "abi_test_harness".to_string()));
    default_header_maps.insert(
        MapType::HttpResponseHeaders as i32,
        http_on_response_headers,
    );

    let mut http_on_response_trailers = Vec::new();
    http_on_response_trailers.push((":method".to_string(), "GET".to_string()));
    http_on_response_trailers.push((
        ":path".to_string(),
        "/default/response/trailers/path".to_string(),
    ));
    http_on_response_trailers.push((":authority".to_string(), "abi_test_harness".to_string()));
    default_header_maps.insert(
        MapType::HttpResponseTrailers as i32,
        http_on_response_trailers,
    );

    let mut http_call_response_headers = Vec::new();
    http_call_response_headers.push((":method".to_string(), "GET".to_string()));
    http_call_response_headers.push((
        ":path".to_string(),
        "/default/call/response/headers/path".to_string(),
    ));
    http_call_response_headers.push((":authority".to_string(), "abi_test_harness".to_string()));
    default_header_maps.insert(
        MapType::HttpCallResponseHeaders as i32,
        http_call_response_headers,
    );

    let mut http_call_response_trailers = Vec::new();
    http_call_response_trailers.push((":method".to_string(), "GET".to_string()));
    http_call_response_trailers.push((
        ":path".to_string(),
        "/default/call/response/trailers/path".to_string(),
    ));
    http_call_response_trailers.push((":authority".to_string(), "abi_test_harness".to_string()));
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
