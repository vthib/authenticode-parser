use std::ptr::null_mut;

use authenticode_parser_sys as sys;

#[repr(transparent)]
pub struct AuthenticodeArray(*mut sys::AuthenticodeArray);

impl Drop for AuthenticodeArray {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Safety: the 0 points to a sys::AuthenticodeArray object
            // allocated by the C library, and it has not been freed before
            // as we replace the 0 with NULL once freed.
            unsafe {
                sys::authenticode_array_free(self.0);
            }
            self.0 = null_mut();
        }
    }
}

impl AuthenticodeArray {
    pub fn iter(&self) -> impl Iterator<Item = Authenticode> {
        let slice = unsafe { std::slice::from_raw_parts((*self.0).signatures, (*self.0).count) };

        slice.iter().map(|v| Authenticode(*v))
    }
}

#[repr(transparent)]
pub struct Authenticode(*const sys::Authenticode);

impl Authenticode {
    pub fn verify_flags(&self) -> Option<AuthenticodeVerify> {
        match unsafe { (*self.0).verify_flags } {
            0 => Some(AuthenticodeVerify::Valid),
            1 => Some(AuthenticodeVerify::CantParse),
            2 => Some(AuthenticodeVerify::NoSignerCert),
            3 => Some(AuthenticodeVerify::DigestMissing),
            4 => Some(AuthenticodeVerify::InternalError),
            5 => Some(AuthenticodeVerify::NoSignerInfo),
            6 => Some(AuthenticodeVerify::WrongPkcs7Type),
            7 => Some(AuthenticodeVerify::BadContent),
            8 => Some(AuthenticodeVerify::Invalid),
            9 => Some(AuthenticodeVerify::WrongFileDigest),
            10 => Some(AuthenticodeVerify::UnknownAlgorithm),
            _ => None,
        }
    }
}

pub enum AuthenticodeVerify {
    /* Signature is valid */
    Valid,
    /* Parsing error (from OpenSSL functions) */
    CantParse,
    /* Signers certificate is missing */
    NoSignerCert,
    /* No digest saved inside the signature */
    DigestMissing,
    /* Non verification errors - allocations etc. */
    InternalError,
    /* SignerInfo part of PKCS7 is missing */
    NoSignerInfo,
    /* PKCS7 doesn't have type of SignedData, can't proceed */
    WrongPkcs7Type,
    /* PKCS7 doesn't have corrent content, can't proceed */
    BadContent,
    /* Contained and calculated digest don't match */
    Invalid,
    /* Signature hash and file hash doesn't match */
    WrongFileDigest,
    /* Unknown algorithm, can't proceed with verification */
    UnknownAlgorithm,
}
