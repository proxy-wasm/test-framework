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

use anyhow::Result;
use wasmtime::*;

pub fn print_boundary(wasm_file: &str) -> Result<()> {
    let store: Store<()> = Store::default();
    let module = Module::from_file(store.engine(), wasm_file)?;
    print_imports(&module);
    print_exports(&module);
    return Ok(());
}

pub fn print_imports(module: &Module) {
    let imports = module.imports();
    println!("This module requires {} imports", imports.len());
    println!("-----------------------------------------------------------------");
    // get details of all imports (in order)
    for (c, item) in imports.enumerate() {
        println!(
            "Import {}: {} -- {} -- {:?}",
            c + 1,
            item.module(),
            item.name(),
            item.ty()
        );
    }
    println!("-----------------------------------------------------------------")
}

pub fn print_exports(module: &Module) {
    let exports = module.exports();
    println!("This module requires {} exports", exports.len());
    println!("-----------------------------------------------------------------");
    // get details of all imports (in order)
    for (c, item) in exports.enumerate() {
        println!("Export {}: {} -- {:?}", c + 1, item.name(), item.ty());
    }
    println!("-----------------------------------------------------------------")
}
