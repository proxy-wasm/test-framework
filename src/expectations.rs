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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Global structure for handling low-level expectation structure (staged)
pub struct ExpectHandle {
    pub staged: Expect,
}

impl ExpectHandle {
    pub fn new() -> ExpectHandle {
        ExpectHandle {
            staged: Expect::new(),
        }
    }

    pub fn update_stage(&mut self) {
        self.staged = Expect::new();
    }

    pub fn assert_stage(&self) {
        if self.staged.expect_count != 0 {
            panic!(
                "Function call failed to consume all expectations - total remaining: {}",
                self.staged.expect_count
            );
        }
    }

    pub fn print_staged(&self) {
        println!("{:?}", self.staged);
    }
}

// Structure for setting low-level expectations over specific host functions
#[derive(Debug)]
pub struct Expect {
    pub expect_count: i32,
    log_message: Vec<(i32, String)>,
    tick_period_millis: Vec<Duration>,
    current_time_nanos: Vec<SystemTime>,
    get_buffer_bytes: Vec<(i32, Bytes)>,
    set_buffer_bytes: Vec<(i32, Bytes)>,
    get_header_map_pairs: Vec<(i32, Bytes)>,
    set_header_map_pairs: Vec<(i32, Bytes)>,
    get_header_map_value: Vec<(i32, String, String)>,
    replace_header_map_value: Vec<(i32, String, String)>,
    remove_header_map_value: Vec<(i32, String)>,
    add_header_map_value: Vec<(i32, String, String)>,

    send_local_response: Vec<(i32, Option<String>, Bytes, i32)>,
    http_call: Vec<(String, Bytes, Option<String>, Bytes, Duration, u32)>,
}

impl Expect {
    pub fn new() -> Expect {
        Expect {
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
        }
    }

    pub fn set_expect_log(&mut self, log_level: i32, log_string: &str) {
        self.expect_count += 1;
        self.log_message.push((log_level, log_string.to_string()));
    }

    pub fn get_expect_log(&mut self, log_level: i32) -> Option<String> {
        match self.log_message.len() {
            0 => None,
            _ => {
                self.expect_count -= 1;
                assert_eq!(log_level, self.log_message[0].0);
                Some(self.log_message.remove(0).1)
            }
        }
    }

    pub fn set_expect_set_tick_period_millis(&mut self, tick_period_millis: u64) {
        self.expect_count += 1;
        self.tick_period_millis
            .push(Duration::from_millis(tick_period_millis));
    }

    pub fn get_expect_set_tick_period_millis(&mut self) -> Option<u128> {
        match self.tick_period_millis.len() {
            0 => None,
            _ => {
                self.expect_count -= 1;
                Some(self.tick_period_millis.remove(0).as_millis())
            }
        }
    }

    pub fn set_expect_get_current_time_nanos(&mut self, current_time_nanos: u64) {
        self.expect_count += 1;
        self.current_time_nanos
            .push(UNIX_EPOCH + Duration::from_nanos(current_time_nanos));
    }

    pub fn get_expect_get_current_time_nanos(&mut self) -> Option<u128> {
        match self.current_time_nanos.len() {
            0 => None,
            _ => {
                self.expect_count -= 1;
                Some(
                    self.current_time_nanos
                        .remove(0)
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                )
            }
        }
    }

    pub fn set_expect_get_buffer_bytes(&mut self, buffer_type: i32, buffer_data: &str) {
        self.expect_count += 1;
        self.get_buffer_bytes
            .push((buffer_type, buffer_data.as_bytes().to_vec()));
    }

    pub fn get_expect_get_buffer_bytes(&mut self, buffer_type: i32) -> Option<Bytes> {
        match self.get_buffer_bytes.len() {
            0 => None,
            _ => {
                self.expect_count -= 1;
                assert_eq!(buffer_type, self.get_buffer_bytes[0].0);
                Some(self.get_buffer_bytes.remove(0).1)
            }
        }
    }

    pub fn set_expect_set_buffer_bytes(&mut self, buffer_type: i32, buffer_data: &str) {
        self.expect_count += 1;
        self.set_buffer_bytes
            .push((buffer_type, buffer_data.as_bytes().to_vec()));
    }

    pub fn get_expect_set_buffer_bytes(&mut self, buffer_type: i32, buffer_data: &[u8]) {
        match self.set_buffer_bytes.len() {
            0 => {}
            _ => {
                self.expect_count -= 1;
                let expect_buffer = self.set_buffer_bytes.remove(0);
                assert_eq!(buffer_type, expect_buffer.0);
                assert_eq!(buffer_data, &expect_buffer.1[..])
            }
        }
    }

    pub fn set_expect_get_header_map_pairs(
        &mut self,
        map_type: i32,
        header_map_pairs: Vec<(&str, &str)>,
    ) {
        self.expect_count += 1;
        self.get_header_map_pairs
            .push((map_type, serialize_map(header_map_pairs)));
    }

    pub fn get_expect_get_header_map_pairs(&mut self, map_type: i32) -> Option<Bytes> {
        match self.get_header_map_pairs.len() {
            0 => None,
            _ => {
                self.expect_count -= 1;
                assert_eq!(map_type, self.get_header_map_pairs[0].0);
                Some(self.get_header_map_pairs.remove(0).1)
            }
        }
    }

    pub fn set_expect_set_header_map_pairs(
        &mut self,
        map_type: i32,
        header_map_pairs: Vec<(&str, &str)>,
    ) {
        self.expect_count += 1;
        self.set_header_map_pairs
            .push((map_type, serialize_map(header_map_pairs)));
    }

    pub fn get_expect_set_header_map_pairs(&mut self, map_type: i32) -> Option<Bytes> {
        match self.set_header_map_pairs.len() {
            0 => None,
            _ => {
                self.expect_count -= 1;
                assert_eq!(map_type, self.set_header_map_pairs[0].0);
                Some(self.set_header_map_pairs.remove(0).1)
            }
        }
    }

    pub fn set_expect_get_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        self.expect_count += 1;
        self.get_header_map_value.push((
            map_type,
            header_map_key.to_string(),
            header_map_value.to_string(),
        ));
    }

    pub fn get_expect_get_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
    ) -> Option<String> {
        match self.get_header_map_value.len() {
            0 => None,
            _ => {
                self.expect_count -= 1;
                assert_eq!(map_type, self.get_header_map_value[0].0);
                assert_eq!(header_map_key, &self.get_header_map_value[0].1);
                Some(self.get_header_map_value.remove(0).2)
            }
        }
    }

    pub fn set_expect_replace_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        self.expect_count += 1;
        self.replace_header_map_value.push((
            map_type,
            header_map_key.to_string(),
            header_map_value.to_string(),
        ));
    }

    pub fn get_expect_replace_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        match self.replace_header_map_value.len() {
            0 => {}
            _ => {
                self.expect_count -= 1;
                let header_map_tuple = self.replace_header_map_value.remove(0);
                assert_eq!(map_type, header_map_tuple.0);
                assert_eq!(header_map_key, &header_map_tuple.1);
                assert_eq!(header_map_value, &header_map_tuple.2);
            }
        }
    }

    pub fn set_expect_remove_header_map_value(&mut self, map_type: i32, header_map_key: &str) {
        self.expect_count += 1;
        self.remove_header_map_value
            .push((map_type, header_map_key.to_string()));
    }

    pub fn get_expect_remove_header_map_value(&mut self, map_type: i32, header_map_key: &str) {
        match self.remove_header_map_value.len() {
            0 => {}
            _ => {
                self.expect_count -= 1;
                let header_map_tuple = self.remove_header_map_value.remove(0);
                assert_eq!(map_type, header_map_tuple.0);
                assert_eq!(header_map_key, &header_map_tuple.1);
            }
        }
    }

    pub fn set_expect_add_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        self.expect_count += 1;
        self.add_header_map_value.push((
            map_type,
            header_map_key.to_string(),
            header_map_value.to_string(),
        ));
    }

    pub fn get_expect_add_header_map_value(
        &mut self,
        map_type: i32,
        header_map_key: &str,
        header_map_value: &str,
    ) {
        match self.add_header_map_value.len() {
            0 => {}
            _ => {
                self.expect_count -= 1;
                let header_map_tuple = self.add_header_map_value.remove(0);
                assert_eq!(map_type, header_map_tuple.0);
                assert_eq!(header_map_key, &header_map_tuple.1);
                assert_eq!(header_map_value, &header_map_tuple.2);
            }
        }
    }

    pub fn set_expect_send_local_response(
        &mut self,
        status_code: i32,
        body: Option<&str>,
        headers: Vec<(&str, &str)>,
        grpc_status: i32,
    ) {
        self.expect_count += 1;
        self.send_local_response.push((
            status_code,
            body.map(|data| data.to_string()),
            serialize_map(headers),
            grpc_status,
        ))
    }

    pub fn get_expect_send_local_response(
        &mut self,
        status_code: i32,
        body: Option<&str>,
        headers: Bytes,
        grpc_status: i32,
    ) {
        match self.send_local_response.len() {
            0 => {}
            _ => {
                self.expect_count -= 1;
                let local_response_tuple = self.send_local_response.remove(0);
                assert_eq!(status_code, local_response_tuple.0);
                assert_eq!(
                    body.unwrap_or("default"),
                    &local_response_tuple.1.unwrap_or(String::from("default"))
                );
                assert_eq!(headers, local_response_tuple.2);
                assert_eq!(grpc_status, local_response_tuple.3);
            }
        }
    }

    pub fn set_expect_http_call(
        &mut self,
        upstream: &str,
        headers: Vec<(&str, &str)>,
        body: Option<&str>,
        trailers: Vec<(&str, &str)>,
        timeout: u64,
        token_id: u32,
    ) {
        self.expect_count += 1;
        self.http_call.push((
            upstream.to_string(),
            serialize_map(headers),
            body.map(|data| data.to_string()),
            serialize_map(trailers),
            Duration::from_millis(timeout),
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
            0 => None,
            _ => {
                self.expect_count -= 1;
                let http_call_tuple = self.http_call.remove(0);
                assert_eq!(upstream, &http_call_tuple.0);
                assert_eq!(headers, &http_call_tuple.1[..]);
                assert_eq!(
                    body.unwrap_or("default"),
                    &http_call_tuple.2.unwrap_or(String::from("default"))
                );
                assert_eq!(trailers, &http_call_tuple.3[..]);
                assert_eq!(timeout, http_call_tuple.4.as_millis() as i32);
                Some(http_call_tuple.5)
            }
        }
    }
}
