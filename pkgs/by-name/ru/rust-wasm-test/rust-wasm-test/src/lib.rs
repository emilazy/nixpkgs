fn udivti3(a: u128, b: u128) -> u128 {
    a / b
}

#[no_mangle]
pub extern "C" fn rust_wasm_test() -> bool {
    use core::hint::black_box as bb;
    return bb(udivti3(bb(4), bb(2))) == 2;
}
