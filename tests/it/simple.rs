use authenticode_parser_sys as sys;

#[test]
fn test_simple() {
    let auth = unsafe {
        sys::initialize_authenticode_parser();
        sys::parse_authenticode(b"".as_ptr(), 0)
    };
    assert!(auth.is_null());
}
