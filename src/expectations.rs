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

use crate::hostcalls::{serial_utils::serialize_map, set_status};
use crate::types::*;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn set_expect_status(checks: bool) {
    if checks {
        set_status(ExpectStatus::Expected)
    } else {
        set_status(ExpectStatus::Failed);
    }
}

// Global structure for handling low-level expectation structure (staged)
pub struct ExpectHandle {
    pub staged: Expect,
}

impl ExpectHandle {
    pub fn new() -> ExpectHandle {
        ExpectHandle {
            staged: Expect::new(false),
        }
    }

    pub fn update_stage(&mut self, allow_unexpected: bool) {
        self.staged = Expect::new(allow_unexpected);
    }

    pub fn assert_stage(&self) -> Option<String> {
        if self.staged.expect_count > 0 {
            return Some(format!(
                "Error: failed to consume all expectations - total remaining: {}",
                self.staged.expect_count
            ));
        } else if self.staged.expect_count < 0 {
            return Some(format!(
                "Error: expectations failed to account for all host calls by {} \n\
            if this is intended, please use --allow-unexpected (-a) mode",
                -1 * self.staged.expect_count
            ));
        }
        None
    }

    pub fn print_staged(&self) {
        println!("{:?}", self.staged);
    }
}

// Structure for setting low-level expectations over specific host functions
#[derive(Debug)]
pub struct Expect {
    allow_unexpected: bool,
    pub expect_count: i32,
    log_message: Vec<(Option<i32>, Option<String>)>,
    tick_period_millis: Vec<Option<Duration>>,
    current_time_nanos: Vec<Option<SystemTime>>,
    get_buffer_bytes: Vec<(Option<i32>, Option<Bytes>)>,
    set_buffer_bytes: Vec<(Option<i32>, Option<Bytes>)>,
    get_header_map_pairs: Vec<(Option<i32>, Option<Bytes>)>,
    set_header_map_pairs: Vec<(Option<i32>, Option<Bytes>)>,
    get_header_map_value: Vec<(Option<i32>, Option<String>, Option<String>)>,
    replace_header_map_value: Vec<(Option<i32>, Option<String>, Option<String>)>,
    remove_header_map_value: Vec<(Option<i32>, Option<String>)>,
    add_header_map_value: Vec<(Option<i32>, Option<String>, Option<String>)>,
    send_local_response: Vec<(Option<i32>, Option<String>, Option<Bytes>, Option<i32>)>,
    http_call: Vec<(
        Option<String>,
        Option<Bytes>,
        Option<String>,
        Option<Bytes>,
        Option<Duration>,
        Option<u32>,
    )>,
    grpc_call: Vec<(
        Option<String>,
        Option<String>,
        Option<String>,
        Option<Bytes>,
        Option<Bytes>,
        Option<Duration>,
        Option<u32>,
    )>,
}

impl Expect {
    pub fn new(allow_unexpected: bool) -> Expect {
        Expect {
            allow_unexpected: allow_unexpected,
            expect_count: 0,
            log_message: vec![],
            tick_period_millis: vec![],
            current_time_nanos: vec![],
            get_buffer_bytes: vec![],
            set_buffer_bytes: vec![],
            get_header_map_pairs: vec![],
            set_header_map_pairs: vec![],
            get_header_map_value: vec![],
            replace_header_map_value: vec![],
            remove_header_map_value: vec![],
            add_header_map_value: vec![],
            send_local_response: vec![],
            http_call: vec![],
            grpc_call: vec![],
        }
    }

    pub fn set_expect_log(&mut self, log_level: Option<i32>, log_string: Option<&str>) {
        self.expect_count += 1;
        self.log_message
            .push((log_level, log_string.map(|s| s.to_string())));
    }

    pub fn get_expect_log(&mut self, log_level: i32, log_string: &str) {
        match self.log_message.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
            }
            _ => {
                self.expect_count -= 1;
                let log_tuple = self.log_message.remove(0);
                let mut expect_status = log_level == log_tuple.0.unwrap_or(log_level);
                expect_status =
                    expect_status && log_string == log_tuple.1.unwrap_or(log_string.to_string());
                set_expect_status(expect_status);
            }
        }
    }

    pub fn set_expect_set_tick_period_millis(&mut self, tick_period_millis: Option<u64>) {
        self.expect_count += 1;
        self.tick_period_millis
            .push(tick_period_millis.map(|period| Duration::from_millis(period)));
    }

    pub fn get_expect_set_tick_period_millis(&mut self, tick_period_millis: u128) {
        match self.tick_period_millis.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
            }
            _ => {
                self.expect_count -= 1;
                let expect_status = tick_period_millis
                    == self
                        .tick_period_millis
                        .remove(0)
                        .map(|period| period.as_millis())
                        .unwrap_or(tick_period_millis);
                set_expect_status(expect_status);
            }
        }
    }

    pub fn set_expect_get_current_time_nanos(&mut self, current_time_nanos: Option<u64>) {
        self.expect_count += 1;
        self.current_time_nanos.push(
            current_time_nanos.map(|time_nanos| UNIX_EPOCH + Duration::from_nanos(time_nanos)),
        );
    }

    pub fn get_expect_get_current_time_nanos(&mut self) -> Option<u128> {
        match self.current_time_nanos.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
                None
            }
            _ => {
                self.expect_count -= 1;
                set_status(ExpectStatus::Expected);
                self.current_time_nanos
                    .remove(0)
                    .map(|time_nanos| time_nanos.duration_since(UNIX_EPOCH).unwrap().as_nanos())
            }
        }
    }

    pub fn set_expect_get_buffer_bytes(
        &mut self,
        buffer_type: Option<i32>,
        buffer_data: Option<&[u8]>,
    ) {
        self.expect_count += 1;
        self.get_buffer_bytes
            .push((buffer_type, buffer_data.map(|data| data.to_vec())));
    }

    pub fn get_expect_get_buffer_bytes(&mut self, buffer_type: i32) -> Option<Bytes> {
        match self.get_buffer_bytes.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
                None
            }
            _ => {
                self.expect_count -= 1;
                let expect_status =
                    buffer_type == self.get_buffer_bytes[0].0.unwrap_or(buffer_type);
                set_expect_status(expect_status);
                self.get_buffer_bytes.remove(0).1
            }
        }
    }

    pub fn set_expect_set_buffer_bytes(
        &mut self,
        buffer_type: Option<i32>,
        buffer_data: Option<&str>,
    ) {
        self.expect_count += 1;
        self.set_buffer_bytes.push((
            buffer_type,
            buffer_data.map(|data| data.as_bytes().to_vec()),
        ));
    }

    pub fn get_expect_set_buffer_bytes(&mut self, buffer_type: i32, buffer_data: &[u8]) {
        match self.set_buffer_bytes.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
            }
            _ => {
                self.expect_count -= 1;
                let expect_buffer = self.set_buffer_bytes.remove(0);
                let mut expect_status = buffer_type == expect_buffer.0.unwrap_or(buffer_type);
                expect_status = expect_status
                    && &buffer_data == &&expect_buffer.1.unwrap_or(buffer_data.to_vec())[..];
                set_expect_status(expect_status);
            }
        }
    }

    pub fn set_expect_get_header_map_pairs(
        &mut self,
        map_type: Option<i32>,
        header_map_pairs: Option<Vec<(&str, &str)>>,
    ) {
        self.expect_count += 1;
        self.get_header_map_pairs
            .push((map_type, header_map_pairs.map(|map| serialize_map(map))));
    }

    pub fn get_expect_get_header_map_pairs(&mut self, map_type: i32) -> Option<Bytes> {
        match self.get_header_map_pairs.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
                None
            }
            _ => {
                self.expect_count -= 1;
                let expect_status = map_type == self.get_header_map_pairs[0].0.unwrap_or(map_type);
                set_expect_status(expect_status);
                self.get_header_map_pairs.remove(0).1
            }
        }
    }

    pub fn set_expect_set_header_map_pairs(
        &mut self,
        map_type: Option<i32>,
        header_map_pairs: Option<Vec<(&str, &str)>>,
    ) {
        self.expect_count += 1;
        self.set_header_map_pairs
            .push((map_type, header_map_pairs.map(|map| serialize_map(map))));
    }

    pub fn get_expect_set_header_map_pairs(&mut self, map_type: i32, header_map_pairs: &[u8]) {
        match self.set_header_map_pairs.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
            }
            _ => {
                self.expect_count -= 1;
                let mut expect_status =
                    map_type == self.set_header_map_pairs[0].0.unwrap_or(map_type);
                expect_status = expect_status
                    && &header_map_pairs
                        == &&self
                            .set_header_map_pairs
                            .remove(0)
                            .1
                            .unwrap_or(header_map_pairs.to_vec())[..];
                set_expect_status(expect_status);
            }
        }
    }

    pub fn set_expect_get_header_map_value(
        &mut self,
        map_type: Option<i32>,
        header_map_key: Option<&str>,
        header_map_value: Option<&str>,
    ) {
        self.expect_count += 1;
        self.get_header_map_value.push((
            map_type,
            header_map_key.map(|key| key.to_string()),
            header_map_value.map(|value| value.to_string()),
        ));
    }

    pub fn get_expect_get_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
    ) -> Option<String> {
        match self.get_header_map_value.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
                None
            }
            _ => {
                self.expect_count -= 1;
                let header_map_tuple = self.get_header_map_value.remove(0);
                let mut expect_status = map_type == header_map_tuple.0.unwrap_or(map_type);
                expect_status = expect_status
                    && header_map_key == &header_map_tuple.1.unwrap_or(header_map_key.to_string());
                set_expect_status(expect_status);
                header_map_tuple.2
            }
        }
    }

    pub fn set_expect_replace_header_map_value(
        &mut self,
        map_type: Option<i32>,
        header_map_key: Option<&str>,
        header_map_value: Option<&str>,
    ) {
        self.expect_count += 1;
        self.replace_header_map_value.push((
            map_type,
            header_map_key.map(|key| key.to_string()),
            header_map_value.map(|value| value.to_string()),
        ));
    }

    pub fn get_expect_replace_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        match self.replace_header_map_value.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
            }
            _ => {
                self.expect_count -= 1;
                let header_map_tuple = self.replace_header_map_value.remove(0);
                let mut expect_status = map_type == header_map_tuple.0.unwrap_or(map_type);
                expect_status = expect_status
                    && header_map_key == &header_map_tuple.1.unwrap_or(header_map_key.to_string());
                expect_status = expect_status
                    && header_map_value
                        == &header_map_tuple.2.unwrap_or(header_map_value.to_string());
                set_expect_status(expect_status);
            }
        }
    }

    pub fn set_expect_remove_header_map_value(
        &mut self,
        map_type: Option<i32>,
        header_map_key: Option<&str>,
    ) {
        self.expect_count += 1;
        self.remove_header_map_value
            .push((map_type, header_map_key.map(|key| key.to_string())));
    }

    pub fn get_expect_remove_header_map_value(&mut self, map_type: i32, header_map_key: &str) {
        match self.remove_header_map_value.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
            }
            _ => {
                self.expect_count -= 1;
                let header_map_tuple = self.remove_header_map_value.remove(0);
                let mut expect_status = map_type == header_map_tuple.0.unwrap_or(map_type);
                expect_status = expect_status
                    && header_map_key == &header_map_tuple.1.unwrap_or(header_map_key.to_string());
                set_expect_status(expect_status);
            }
        }
    }

    pub fn set_expect_add_header_map_value(
        &mut self,
        map_type: Option<i32>,
        header_map_key: Option<&str>,
        header_map_value: Option<&str>,
    ) {
        self.expect_count += 1;
        self.add_header_map_value.push((
            map_type,
            header_map_key.map(|key| key.to_string()),
            header_map_value.map(|value| value.to_string()),
        ));
    }

    pub fn get_expect_add_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        match self.add_header_map_value.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
            }
            _ => {
                self.expect_count -= 1;
                let header_map_tuple = self.add_header_map_value.remove(0);
                let mut expect_status = map_type == header_map_tuple.0.unwrap_or(map_type);
                expect_status = expect_status
                    && header_map_key == &header_map_tuple.1.unwrap_or(header_map_key.to_string());
                expect_status = expect_status
                    && header_map_value
                        == &header_map_tuple.2.unwrap_or(header_map_value.to_string());
                set_expect_status(expect_status);
            }
        }
    }

    pub fn set_expect_send_local_response(
        &mut self,
        status_code: Option<i32>,
        body: Option<&str>,
        headers: Option<Vec<(&str, &str)>>,
        grpc_status: Option<i32>,
    ) {
        self.expect_count += 1;
        self.send_local_response.push((
            status_code,
            body.map(|data| data.to_string()),
            headers.map(|data| serialize_map(data)),
            grpc_status,
        ))
    }

    pub fn get_expect_send_local_response(
        &mut self,
        status_code: i32,
        body: Option<&str>,
        headers: &[u8],
        grpc_status: i32,
    ) {
        match self.send_local_response.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
            }
            _ => {
                self.expect_count -= 1;
                let local_response_tuple = self.send_local_response.remove(0);
                let mut expect_status =
                    status_code == local_response_tuple.0.unwrap_or(status_code);
                expect_status = expect_status
                    && body.unwrap_or("default")
                        == &local_response_tuple
                            .1
                            .unwrap_or(body.unwrap_or("default").to_string());
                expect_status = expect_status
                    && &headers == &&local_response_tuple.2.unwrap_or(headers.to_vec())[..];
                expect_status =
                    expect_status && grpc_status == local_response_tuple.3.unwrap_or(grpc_status);
                set_expect_status(expect_status);
            }
        }
    }

    pub fn set_expect_http_call(
        &mut self,
        upstream: Option<&str>,
        headers: Option<Vec<(&str, &str)>>,
        body: Option<&str>,
        trailers: Option<Vec<(&str, &str)>>,
        timeout: Option<u64>,
        token_id: Option<u32>,
    ) {
        self.expect_count += 1;
        self.http_call.push((
            upstream.map(|data| data.to_string()),
            headers.map(|data| serialize_map(data)),
            body.map(|data| data.to_string()),
            trailers.map(|data| serialize_map(data)),
            timeout.map(|data| Duration::from_millis(data)),
            token_id,
        ));
    }

    pub fn get_expect_http_call(
        &mut self,
        upstream: &str,
        headers: &[u8],
        body: Option<&str>,
        trailers: &[u8],
        timeout: i32,
    ) -> Option<u32> {
        match self.http_call.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
                None
            }
            _ => {
                self.expect_count -= 1;
                let http_call_tuple = self.http_call.remove(0);
                let mut expect_status =
                    upstream == &http_call_tuple.0.unwrap_or(upstream.to_string());
                expect_status = expect_status
                    && &headers == &&http_call_tuple.1.unwrap_or(headers.to_vec())[..];
                expect_status = expect_status
                    && body.unwrap_or("default")
                        == &http_call_tuple
                            .2
                            .unwrap_or(body.unwrap_or("default").to_string());
                expect_status = expect_status
                    && &trailers == &&http_call_tuple.3.unwrap_or(trailers.to_vec())[..];
                expect_status = expect_status
                    && timeout
                        == http_call_tuple
                            .4
                            .map(|data| data.as_millis() as i32)
                            .unwrap_or(timeout);
                set_expect_status(expect_status);
                http_call_tuple.5
            }
        }
    }

    pub fn set_expect_grpc_call(
        &mut self,
        service: Option<&str>,
        service_name: Option<&str>,
        method_name: Option<&str>,
        initial_metadata: Option<&[u8]>,
        request: Option<&[u8]>,
        timeout: Option<u64>,
        token_id: Option<u32>,
    ) {
        self.expect_count += 1;
        self.grpc_call.push((
            service.map(ToString::to_string),
            service_name.map(ToString::to_string),
            method_name.map(ToString::to_string),
            initial_metadata.map(|s| s.to_vec()),
            request.map(|s| s.to_vec()),
            timeout.map(Duration::from_millis),
            token_id,
        ));
    }

    pub fn get_expect_grpc_call(
        &mut self,
        service: String,
        service_name: String,
        method: String,
        initial_metadata: &[u8],
        request: &[u8],
        timeout: i32,
    ) -> Option<u32> {
        match self.grpc_call.len() {
            0 => {
                if !self.allow_unexpected {
                    self.expect_count -= 1;
                }
                set_status(ExpectStatus::Unexpected);
                None
            }
            _ => {
                self.expect_count -= 1;
                let (
                    expected_service,
                    expected_service_name,
                    expected_method,
                    expected_initial_metadata,
                    expected_request,
                    expected_duration,
                    result,
                ) = self.grpc_call.remove(0);

                let expected = expected_service.map(|e| e == service).unwrap_or(true)
                    && expected_service_name
                        .map(|e| e == service_name)
                        .unwrap_or(true)
                    && expected_method.map(|e| e == method).unwrap_or(true)
                    && expected_initial_metadata
                        .map(|e| e == initial_metadata)
                        .unwrap_or(true)
                    && expected_request.map(|e| e == request).unwrap_or(true)
                    && expected_duration
                        .map(|e| e.as_millis() as i32 == timeout)
                        .unwrap_or(true);
                set_expect_status(expected);
                return result;
            }
        }
    }
}
