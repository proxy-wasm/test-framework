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

#[repr(u32)]
#[derive(Debug)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum Action {
    Continue = 0,
    Pause = 1,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum GrpcStatus {
    Ok = 0,
    Canceled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
    InvalidCode = -1,
}

#[repr(u32)]
#[derive(Debug)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    BadArgument = 2,
    Empty = 7,
    CasMismatch = 8,
    InternalFailure = 10,
}

#[repr(u32)]
#[derive(Debug)]
pub enum MetricType {
    Counter = 0,
    Gauge = 1,
    Histogram = 2,
}

#[repr(u32)]
#[derive(Debug)]
pub enum CloseType {
    Unknown = 0,
    Local = 1,  // Close initiated by the proxy.
    Remote = 2, // Close initiated by the peer.
}

#[repr(u32)]
#[derive(Debug)]
pub enum BufferType {
    HttpRequestBody = 0,
    HttpResponseBody = 1,
    DownstreamData = 2,
    UpstreamData = 3,
    HttpCallResponseBody = 4,
    GrpcReceiveBuffer = 5,
    VmConfiguration = 6,
    PluginConfiguration = 7,
}

#[repr(u32)]
#[derive(Debug)]
pub enum MapType {
    HttpRequestHeaders = 0,
    HttpRequestTrailers = 1,
    HttpResponseHeaders = 2,
    HttpResponseTrailers = 3,
    HttpCallResponseHeaders = 6,
    HttpCallResponseTrailers = 7,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PeerType {
    Unknown = 0,
    Local = 1,
    Remote = 2,
}

#[derive(Debug)]
pub enum ReturnType {
    None,
    Bool(bool),
    Action(Action),
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum AbiVersion {
    UnknownAbiVersion,
    ProxyAbiVersion0_1_0,
    ProxyAbiVersion0_2_0,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ExpectStatus {
    Expected,
    Failed,
    Unexpected,
}

pub type Bytes = Vec<u8>;
