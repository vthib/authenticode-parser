use std::{ffi::CStr, ptr::null_mut};

use authenticode_parser_sys as sys;

pub fn initialize() {
    unsafe { sys::initialize_authenticode_parser() }
}

pub fn parse(data: &[u8]) -> Option<AuthenticodeArray> {
    let res = unsafe { sys::authenticode_new(data.as_ptr(), data.len() as _) };
    if res.is_null() {
        None
    } else {
        Some(AuthenticodeArray(res))
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct AuthenticodeArray(*mut sys::AuthenticodeArray);

impl Drop for AuthenticodeArray {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                sys::authenticode_array_free(self.0);
            }
            self.0 = null_mut();
        }
    }
}

impl AuthenticodeArray {
    pub fn signatures(&self) -> &[Authenticode] {
        unsafe { std::slice::from_raw_parts((*self.0).signatures.cast(), (*self.0).count) }
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct Authenticode<'a>(&'a sys::Authenticode);

impl Authenticode<'_> {
    /// Flags related to verification.
    pub fn verify_flags(&self) -> Option<AuthenticodeVerify> {
        match self.0.verify_flags {
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

    /// Raw PCKS7 version.
    pub fn version(&self) -> i32 {
        self.0.version
    }

    /// Name of the digest algorithm.
    pub fn digest_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.digest_alg)
    }

    /// File digest stored in the signature.
    pub fn digest(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.digest)
    }

    /// Actual calculated file digest.
    pub fn file_digest(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.file_digest)
    }

    /// SignerInfo information of the authenticode
    pub fn signer(&self) -> Option<Signer> {
        if self.0.signer.is_null() {
            None
        } else {
            Some(Signer(unsafe { &*self.0.signer }))
        }
    }

    /// All certificates in the Signature.
    ///
    /// This includes the ones in timestamp countersignatures.
    pub fn certs(&self) -> &[Certificate] {
        if self.0.certs.is_null() {
            &[]
        } else {
            unsafe {
                std::slice::from_raw_parts((*self.0.certs).certs.cast(), (*self.0.certs).count)
            }
        }
    }

    /// Timestamp countersignatures.
    pub fn countersigs(&self) -> &[Countersignature] {
        if self.0.countersigs.is_null() {
            &[]
        } else {
            unsafe {
                std::slice::from_raw_parts(
                    (*self.0.countersigs).counters.cast(),
                    (*self.0.countersigs).count,
                )
            }
        }
    }
}

/// Represents SignerInfo structure.
#[repr(transparent)]
#[derive(Debug)]
pub struct Signer<'a>(&'a sys::Signer);

impl Signer<'_> {
    /// Message Digest of the SignerInfo
    pub fn digest(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.digest)
    }

    /// Name of the digest algorithm.
    pub fn digest_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.digest_alg)
    }

    /// Program name stored in SpcOpusInfo structure of Authenticode */
    pub fn program_name(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.program_name)
    }

    /// Certificate chain of the signer
    pub fn certificate_chain(&self) -> &[Certificate] {
        if self.0.chain.is_null() {
            &[]
        } else {
            unsafe {
                std::slice::from_raw_parts((*self.0.chain).certs.cast(), (*self.0.chain).count)
            }
        }
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct Countersignature<'a>(&'a sys::Countersignature);

impl Countersignature<'_> {
    /// Countersignature verify flags.
    pub fn verify_flags(&self) -> Option<CounterSignatureVerify> {
        match self.0.verify_flags {
            0 => Some(CounterSignatureVerify::Valid),
            1 => Some(CounterSignatureVerify::CantParse),
            2 => Some(CounterSignatureVerify::NoSignerCert),
            3 => Some(CounterSignatureVerify::UnknownAlgorithm),
            4 => Some(CounterSignatureVerify::Invalid),
            5 => Some(CounterSignatureVerify::CantDecryptDigest),
            6 => Some(CounterSignatureVerify::DigestMissing),
            7 => Some(CounterSignatureVerify::DoesntMatchSignature),
            8 => Some(CounterSignatureVerify::InternalError),
            9 => Some(CounterSignatureVerify::TimeMissing),
            _ => None,
        }
    }

    /// Signing time of the timestamp countersignature.
    pub fn sign_time(&self) -> i64 {
        self.0.sign_time
    }

    /// Name of the digest algorithm.
    pub fn digest_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.digest_alg)
    }

    /// Stored message digest.
    pub fn digest(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.digest)
    }

    /// Certificate chain of the signer
    pub fn certificate_chain(&self) -> &[Certificate] {
        if self.0.chain.is_null() {
            &[]
        } else {
            unsafe {
                std::slice::from_raw_parts((*self.0.chain).certs.cast(), (*self.0.chain).count)
            }
        }
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct Certificate<'a>(&'a sys::Certificate);

impl Certificate<'_> {
    /// Raw version of X509.
    pub fn version(&self) -> i64 {
        i64::from(self.0.version)
    }

    /// Oneline name of Issuer.
    pub fn issuer(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.issuer)
    }
    /// Oneline name of Subject.
    pub fn subject(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.subject)
    }
    /// Serial number in format 00:01:02:03:04...
    pub fn serial(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.serial)
    }

    /// SHA1 of the DER representation of the cert.
    pub fn sha1(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.sha1)
    }

    /// SHA256 of the DER representation of the cert.
    pub fn sha256(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.sha256)
    }

    /// Name of the key algorithm.
    pub fn key_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.key_alg)
    }

    /// Name of the signature algorithm.
    pub fn sig_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.sig_alg)
    }

    /// OID of the signature algorithm.
    pub fn sig_alg_oid(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.sig_alg_oid)
    }

    /// NotBefore validity.
    pub fn not_before(&self) -> i64 {
        self.0.not_before
    }

    /// NotAfter validity.
    pub fn not_after(&self) -> i64 {
        self.0.not_after
    }

    /// PEM encoded public key.
    pub fn key(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.key)
    }

    /// Parsed X509 Attributes of Issuer.
    pub fn issuer_attrs(&self) -> Attributes {
        Attributes(&self.0.issuer_attrs)
    }

    /// Parsed X509 Attributes of Subject.
    pub fn subject_attrs(&self) -> Attributes {
        Attributes(&self.0.subject_attrs)
    }
}

/// Various X509 attributes parsed out in raw bytes.
pub struct Attributes<'a>(&'a sys::Attributes);

impl Attributes<'_> {
    pub fn country(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.country)
    }

    pub fn organization(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.organization)
    }

    pub fn organizational_unit(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.organizationalUnit)
    }

    pub fn name_qualifier(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.nameQualifier)
    }

    pub fn state(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.state)
    }

    pub fn common_name(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.commonName)
    }

    pub fn serial_number(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.serialNumber)
    }

    pub fn locality(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.locality)
    }

    pub fn title(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.title)
    }

    pub fn surname(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.surname)
    }

    pub fn given_name(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.givenName)
    }

    pub fn initials(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.initials)
    }

    pub fn pseudonym(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.pseudonym)
    }

    pub fn generation_qualifier(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.generationQualifier)
    }

    pub fn email_address(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.emailAddress)
    }
}

fn byte_array_to_slice(digest: &sys::ByteArray) -> Option<&[u8]> {
    if digest.data.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(digest.data, digest.len as usize) })
    }
}

fn cstr_ptr_to_slice(ptr: &*mut i8) -> Option<&[u8]> {
    if ptr.is_null() {
        None
    } else {
        let cstr = unsafe { CStr::from_ptr(ptr.cast()) };
        Some(cstr.to_bytes())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CounterSignatureVerify {
    /// Countersignature is valid
    Valid,
    /// Parsing error (from OpenSSL functions)
    CantParse,
    /// Signers certificate is missing
    NoSignerCert,
    /// Unknown algorithm, can't proceed with verification
    UnknownAlgorithm,
    /// Verification failed, digest mismatch
    Invalid,
    /// Failed to decrypt countersignature enc_digest for verification
    CantDecryptDigest,
    /// No digest saved inside the countersignature
    DigestMissing,
    /// Message digest inside countersignature doesn't match signature it countersigns
    DoesntMatchSignature,
    /// Non verification errors - allocations etc.
    InternalError,
    /// Time is missing in the timestamp signature
    TimeMissing,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthenticodeVerify {
    /// Signature is valid
    Valid,
    /// Parsing error (from OpenSSL functions)
    CantParse,
    /// Signers certificate is missing
    NoSignerCert,
    /// No digest saved inside the signature
    DigestMissing,
    /// Non verification errors - allocations etc.
    InternalError,
    /// SignerInfo part of PKCS7 is missing
    NoSignerInfo,
    /// PKCS7 doesn't have type of SignedData, can't proceed
    WrongPkcs7Type,
    /// PKCS7 doesn't have corrent content, can't proceed
    BadContent,
    /// Contained and calculated digest don't match
    Invalid,
    /// Signature hash and file hash doesn't match
    WrongFileDigest,
    /// Unknown algorithm, can't proceed with verification
    UnknownAlgorithm,
}
