
# OCaml on WASM

This is a forked version of [OCaml](https://github.com/ocaml/ocaml), aimed to be compiled to WASM.

## Compilation

### Before

Install Emscripten

Follow the [official instructions](https://emscripten.org/).

### Compile

```
emconfigure ./configure
cd runtime
emmake make ocamlruntime
````

So you get `ocamlrun.js` and `ocamlrun.wasm`

## Embedded libraries

- unix/Offical Version 4.12.0
- systhreads/Offical Version 4.12.0
- [integeres](https://github.com/ocamllabs/ocaml-integers)/0.14.0
- [ctypes](https://github.com/ocamllabs/ocaml-ctypes)/0.18.0
- [base](https://github.com/janestreet/base)/0.14.0
- [core_kernel](https://github.com/janestreet/core_kernel)/0.14.0
