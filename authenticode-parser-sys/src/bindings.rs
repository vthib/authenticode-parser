/* automatically generated by rust-bindgen 0.69.2 */

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ByteArray {
    pub data: *mut u8,
    pub len: ::std::os::raw::c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Attributes {
    pub country: ByteArray,
    pub organization: ByteArray,
    pub organizationalUnit: ByteArray,
    pub nameQualifier: ByteArray,
    pub state: ByteArray,
    pub commonName: ByteArray,
    pub serialNumber: ByteArray,
    pub locality: ByteArray,
    pub title: ByteArray,
    pub surname: ByteArray,
    pub givenName: ByteArray,
    pub initials: ByteArray,
    pub pseudonym: ByteArray,
    pub generationQualifier: ByteArray,
    pub emailAddress: ByteArray,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Certificate {
    pub version: ::std::os::raw::c_long,
    pub issuer: *mut ::std::os::raw::c_char,
    pub subject: *mut ::std::os::raw::c_char,
    pub serial: *mut ::std::os::raw::c_char,
    pub sha1: ByteArray,
    pub sha256: ByteArray,
    pub key_alg: *mut ::std::os::raw::c_char,
    pub sig_alg: *mut ::std::os::raw::c_char,
    pub sig_alg_oid: *mut ::std::os::raw::c_char,
    pub not_before: i64,
    pub not_after: i64,
    pub key: *mut ::std::os::raw::c_char,
    pub issuer_attrs: Attributes,
    pub subject_attrs: Attributes,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CertificateArray {
    pub certs: *mut *mut Certificate,
    pub count: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Countersignature {
    pub verify_flags: ::std::os::raw::c_int,
    pub sign_time: i64,
    pub digest_alg: *mut ::std::os::raw::c_char,
    pub digest: ByteArray,
    pub chain: *mut CertificateArray,
    pub certs: *mut CertificateArray,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CountersignatureArray {
    pub counters: *mut *mut Countersignature,
    pub count: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Signer {
    pub digest: ByteArray,
    pub digest_alg: *mut ::std::os::raw::c_char,
    pub program_name: *mut ::std::os::raw::c_char,
    pub chain: *mut CertificateArray,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Authenticode {
    pub verify_flags: ::std::os::raw::c_int,
    pub version: ::std::os::raw::c_int,
    pub digest_alg: *mut ::std::os::raw::c_char,
    pub digest: ByteArray,
    pub file_digest: ByteArray,
    pub signer: *mut Signer,
    pub certs: *mut CertificateArray,
    pub countersigs: *mut CountersignatureArray,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct AuthenticodeArray {
    pub signatures: *mut *mut Authenticode,
    pub count: usize,
}

extern "C" {
    #[doc = " @brief Initializes all globals OpenSSl objects we need for parsing, this is not thread-safe and\n        needs to be called only once, before any multithreading environment\n        https://github.com/openssl/openssl/issues/13524"]
    pub fn initialize_authenticode_parser();

    #[doc = " @brief Constructs AuthenticodeArray from PE file data. Authenticode can\n        contains nested Authenticode signatures as its unsigned attribute,\n        which can also contain nested signatures. For this reason the function returns\n        an Array of parsed Authenticode signatures. Any field of the parsed out\n        structures can be NULL, depending on the input data.\n        Verification result is stored in verify_flags with the first verification error.\n\n @param pe_data PE binary data\n @param pe_len\n @return AuthenticodeArray*"]
    pub fn parse_authenticode(pe_data: *const u8, pe_len: u64) -> *mut AuthenticodeArray;

    #[doc = " @brief Constructs AuthenticodeArray from binary data containing Authenticode\n        signature. Authenticode can contains nested Authenticode signatures\n        as its unsigned attribute, which can also contain nested signatures.\n        For this reason the function return an Array of parsed Authenticode signatures.\n        Any field of the parsed out structures can be NULL, depending on the input data.\n        WARNING: in case of this interface, the file and signature digest comparison is\n        up to the library user, as there is no pe data to calculate file digest from.\n        Verification result is stored in verify_flags with the first verification error\n\n @param data Binary data containing Authenticode signature\n @param len\n @return AuthenticodeArray*"]
    pub fn authenticode_new(data: *const u8, len: i32) -> *mut AuthenticodeArray;

    #[doc = " @brief Deallocates AuthenticodeArray and all it's allocated members\n\n @param auth"]
    pub fn authenticode_array_free(auth: *mut AuthenticodeArray);
}
