use authenticode_parser_sys as sys;

use crate::get_init_token;

#[test]
fn test_simple() {
    let _token = get_init_token();

    let auth = unsafe { sys::ap_parse_authenticode(b"".as_ptr(), 0) };
    assert!(auth.is_null());
}
