use authenticode_parser_sys as sys;

#[test]
fn test_simple() {
    let auth = unsafe {
        sys::ap_initialize_authenticode_parser();
        sys::ap_parse_authenticode(b"".as_ptr(), 0)
    };
    assert!(auth.is_null());
}
