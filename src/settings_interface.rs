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


pub struct DefaultBufferBytes<'a> {
    tester: &'a mut Tester,
    buffer_type: i32,
}

impl<'a> DefaultBufferBytes<'a> {

    pub fn expecting(tester: &'a mut Tester, buffer_type: i32) -> DefaultBufferBytes {
        DefaultBufferBytes {
            tester: tester,
            buffer_type: buffer_type,
        }
    }

    pub fn returning(&mut self, buffer_data: &str) -> &mut Tester {
        self.tester.get_settings_handle().staged.set_buffer_bytes(self.buffer_type, buffer_data);
        self.tester
    }
}


pub struct DefaultHeaderMapPairs<'a> {
    tester: &'a mut Tester,
    map_type: i32,
}

impl<'a> DefaultHeaderMapPairs<'a> {

    pub fn expecting(tester: &'a mut Tester, map_type: i32) -> DefaultHeaderMapPairs {
        DefaultHeaderMapPairs {
            tester: tester,
            map_type: map_type,
        }
    }

    pub fn returning(&mut self, header_map_pairs: Vec<(&str, &str)>) -> &mut Tester {
        self.tester.get_settings_handle().staged.set_header_map_pairs(self.map_type, header_map_pairs);
        self.tester
    }
}
