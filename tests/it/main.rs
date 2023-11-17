use std::sync::Mutex;

mod conformance;
mod simple;

// Used to prevent multiple tests from initializing at the same time, which is forbidden and
// leads to UB.
fn get_init_token() -> authenticode_parser::InitializationToken {
    static INIT_TOKEN: Mutex<Option<authenticode_parser::InitializationToken>> = Mutex::new(None);

    let mut token = INIT_TOKEN.lock().unwrap();
    *token.get_or_insert_with(|| unsafe { authenticode_parser::InitializationToken::new() })
}
