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

use crate::tester::Tester;

// As of now, the following expectations do not require "fn returning()" implementations and hence
// no structure is provided for them. Setting of these expectations are built directly into tester.rs:
// proxy_log(), proxy_set_tick_period_millis(), proxy_set_buffer_bytes(), proxy_set_header_map_pairs,
// proxy_replace_header_map_value(), proxy_remove_header_map_value(), proxy_add_header_map_value(),
// proxy_send_local_response(), etc.

pub struct ExpectGetCurrentTimeNanos<'a> {
    tester: &'a mut Tester,
}

impl<'a> ExpectGetCurrentTimeNanos<'a> {
    pub fn expecting(tester: &'a mut Tester) -> ExpectGetCurrentTimeNanos {
        ExpectGetCurrentTimeNanos { tester: tester }
    }

    pub fn returning(&mut self, current_time_nanos: Option<u64>) -> &mut Tester {
        self.tester
            .get_expect_handle()
            .staged
            .set_expect_get_current_time_nanos(current_time_nanos);
        self.tester
    }
}

pub struct ExpectGetBufferBytes<'a> {
    tester: &'a mut Tester,
    buffer_type: Option<i32>,
}

impl<'a> ExpectGetBufferBytes<'a> {
    pub fn expecting(tester: &'a mut Tester, buffer_type: Option<i32>) -> ExpectGetBufferBytes {
        ExpectGetBufferBytes {
            tester: tester,
            buffer_type: buffer_type,
        }
    }

    pub fn returning(&mut self, buffer_data: Option<&[u8]>) -> &mut Tester {
        self.tester
            .get_expect_handle()
            .staged
            .set_expect_get_buffer_bytes(self.buffer_type, buffer_data);
        self.tester
    }
}

pub struct ExpectGetHeaderMapPairs<'a> {
    tester: &'a mut Tester,
    map_type: Option<i32>,
}

impl<'a> ExpectGetHeaderMapPairs<'a> {
    pub fn expecting(tester: &'a mut Tester, map_type: Option<i32>) -> ExpectGetHeaderMapPairs {
        ExpectGetHeaderMapPairs {
            tester: tester,
            map_type: map_type,
        }
    }

    pub fn returning(&mut self, header_map_pairs: Option<Vec<(&str, &str)>>) -> &mut Tester {
        self.tester
            .get_expect_handle()
            .staged
            .set_expect_get_header_map_pairs(self.map_type, header_map_pairs);
        self.tester
    }
}

pub struct ExpectGetHeaderMapValue<'a> {
    tester: &'a mut Tester,
    map_type: Option<i32>,
    header_map_key: Option<&'static str>,
}

impl<'a> ExpectGetHeaderMapValue<'a> {
    pub fn expecting(
        tester: &'a mut Tester,
        map_type: Option<i32>,
        header_map_key: Option<&'static str>,
    ) -> ExpectGetHeaderMapValue<'a> {
        ExpectGetHeaderMapValue {
            tester: tester,
            map_type: map_type,
            header_map_key: header_map_key,
        }
    }

    pub fn returning(&mut self, header_map_value: Option<&str>) -> &mut Tester {
        self.tester
            .get_expect_handle()
            .staged
            .set_expect_get_header_map_value(self.map_type, self.header_map_key, header_map_value);
        self.tester
    }
}

pub struct ExpectHttpCall<'a> {
    tester: &'a mut Tester,
    upstream: Option<&'a str>,
    headers: Option<Option<Vec<(&'a str, &'a str)>>>,
    body: Option<&'a str>,
    trailers: Option<Option<Vec<(&'a str, &'a str)>>>,
    timeout: Option<u64>,
}

impl<'a> ExpectHttpCall<'a> {
    pub fn expecting(
        tester: &'a mut Tester,
        upstream: Option<&'a str>,
        headers: Option<Vec<(&'a str, &'a str)>>,
        body: Option<&'a str>,
        trailers: Option<Vec<(&'a str, &'a str)>>,
        timeout: Option<u64>,
    ) -> ExpectHttpCall<'a> {
        ExpectHttpCall {
            tester: tester,
            upstream: upstream,
            headers: Some(headers),
            body: body,
            trailers: Some(trailers),
            timeout: timeout,
        }
    }

    pub fn returning(&mut self, token_id: Option<u32>) -> &mut Tester {
        self.tester.get_expect_handle().staged.set_expect_http_call(
            self.upstream,
            self.headers.take().unwrap(),
            self.body,
            self.trailers.take().unwrap(),
            self.timeout,
            token_id,
        );
        self.tester
    }
}

pub struct ExpectGrpcCall<'a> {
    tester: &'a mut Tester,
    service: Option<&'a str>,
    service_name: Option<&'a str>,
    method_name: Option<&'a str>,
    initial_metadata: Option<&'a [u8]>,
    request: Option<&'a [u8]>,
    timeout: Option<u64>,
}

impl<'a> ExpectGrpcCall<'a> {
    pub fn expecting(
        tester: &'a mut Tester,
        service: Option<&'a str>,
        service_name: Option<&'a str>,
        method_name: Option<&'a str>,
        initial_metadata: Option<&'a [u8]>,
        request: Option<&'a [u8]>,
        timeout: Option<u64>,
    ) -> Self {
        Self {
            tester,
            service,
            service_name,
            method_name,
            initial_metadata,
            request,
            timeout,
        }
    }

    pub fn returning(&mut self, token_id: Option<u32>) -> &mut Tester {
        self.tester.get_expect_handle().staged.set_expect_grpc_call(
            self.service,
            self.service_name,
            self.method_name,
            self.initial_metadata,
            self.request,
            self.timeout,
            token_id,
        );
        self.tester
    }
}

pub struct ExpectGetProperty<'a> {
    tester: &'a mut Tester,
    path: Option<Vec<&'static str>>,
}

impl<'a> ExpectGetProperty<'a> {
    pub fn expecting(
        tester: &'a mut Tester,
        path: Option<Vec<&'static str>>,
    ) -> ExpectGetProperty<'a> {
        ExpectGetProperty { tester, path }
    }

    pub fn returning(&mut self, property_data: Option<&[u8]>) -> &mut Tester {
        self.tester
            .get_expect_handle()
            .staged
            .set_expect_get_property(self.path.clone(), property_data);
        self.tester
    }
}
