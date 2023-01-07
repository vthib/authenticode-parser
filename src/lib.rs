//! Bindings for the
//! [authenticode parser library](https://github.com/avast/authenticode-parser) from Avast.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(missing_docs)]
#![deny(clippy::cargo)]

use std::ffi::CStr;
use std::ptr::null_mut;

use authenticode_parser_sys as sys;

/// Initialize the parser.
///
/// Initializes all globals `OpenSSl` objects we need for parsing, this is not thread-safe and
/// needs to be called only once, before any multithreading environment.
/// See <https://github.com/openssl/openssl/issues/13524>.
pub fn initialize() {
    unsafe { sys::initialize_authenticode_parser() }
}

/// Constructs `AuthenticodeArray` from binary data containing Authenticode signature.
///
/// Authenticode can contains nested Authenticode signatures as its unsigned attribute, which
/// can also contain nested signatures. For this reason the function return an Array of parsed
/// Authenticode signatures.
///
/// Any field of the parsed out structures can be NULL, depending on the input data.
///
/// WARNING: in case of this interface, the file and signature digest comparison is up to the
/// library user, as there is no pe data to calculate file digest from.
///
/// Verification result is stored in `verify_flags` with the first verification error.
#[must_use]
pub fn parse(data: &[u8]) -> Option<AuthenticodeArray> {
    let res = unsafe { sys::authenticode_new(data.as_ptr(), data.len() as _) };
    if res.is_null() {
        None
    } else {
        Some(AuthenticodeArray(res))
    }
}

/// Constructs `AuthenticodeArray` from PE file data.
///
/// Authenticode can contains nested Authenticode signatures as its unsigned attribute, which can
/// also contain nested signatures. For this reason the function returns an Array of parsed
/// Authenticode signatures.
///
/// Any field of the parsed out structures can be NULL, depending on the input data.
///
/// Verification result is stored in `verify_flags` with the first verification error.
#[must_use]
pub fn parse_pe(data: &[u8]) -> Option<AuthenticodeArray> {
    let res = unsafe { sys::parse_authenticode(data.as_ptr(), data.len() as _) };
    if res.is_null() {
        None
    } else {
        Some(AuthenticodeArray(res))
    }
}

/// Array of authenticode signatures.
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
    /// Array of authenticode signatures.
    #[must_use]
    pub fn signatures(&self) -> &[Authenticode] {
        unsafe { std::slice::from_raw_parts((*self.0).signatures.cast(), (*self.0).count) }
    }
}

/// Authenticode signature.
#[repr(transparent)]
#[derive(Debug)]
pub struct Authenticode<'a>(&'a sys::Authenticode);

impl Authenticode<'_> {
    /// Flags related to verification.
    #[must_use]
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
    #[must_use]
    pub fn version(&self) -> i32 {
        self.0.version
    }

    /// Name of the digest algorithm.
    #[must_use]
    pub fn digest_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.digest_alg)
    }

    /// File digest stored in the signature.
    #[must_use]
    pub fn digest(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.digest)
    }

    /// Actual calculated file digest.
    #[must_use]
    pub fn file_digest(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.file_digest)
    }

    /// `SignerInfo` information of the authenticode
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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

/// Represents `SignerInfo` structure.
#[repr(transparent)]
#[derive(Debug)]
pub struct Signer<'a>(&'a sys::Signer);

impl Signer<'_> {
    /// Message Digest of the `SignerInfo`
    #[must_use]
    pub fn digest(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.digest)
    }

    /// Name of the digest algorithm.
    #[must_use]
    pub fn digest_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.digest_alg)
    }

    /// Program name stored in `SpcOpusInfo` structure of Authenticode */
    #[must_use]
    pub fn program_name(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.program_name)
    }

    /// Certificate chain of the signer
    #[must_use]
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

/// Authenticode counter signature.
#[repr(transparent)]
#[derive(Debug)]
pub struct Countersignature<'a>(&'a sys::Countersignature);

impl Countersignature<'_> {
    /// Countersignature verify flags.
    #[must_use]
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
    #[must_use]
    pub fn sign_time(&self) -> i64 {
        self.0.sign_time
    }

    /// Name of the digest algorithm.
    #[must_use]
    pub fn digest_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.digest_alg)
    }

    /// Stored message digest.
    #[must_use]
    pub fn digest(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.digest)
    }

    /// Certificate chain of the signer
    #[must_use]
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

/// Authenticode certificate.
#[repr(transparent)]
#[derive(Debug)]
pub struct Certificate<'a>(&'a sys::Certificate);

impl Certificate<'_> {
    /// Raw version of X509.
    #[must_use]
    pub fn version(&self) -> i64 {
        self.0.version
    }

    /// Oneline name of Issuer.
    #[must_use]
    pub fn issuer(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.issuer)
    }
    /// Oneline name of Subject.
    #[must_use]
    pub fn subject(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.subject)
    }
    /// Serial number in format 00:01:02:03:04...
    #[must_use]
    pub fn serial(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.serial)
    }

    /// SHA1 of the DER representation of the cert.
    #[must_use]
    pub fn sha1(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.sha1)
    }

    /// SHA256 of the DER representation of the cert.
    #[must_use]
    pub fn sha256(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.sha256)
    }

    /// Name of the key algorithm.
    #[must_use]
    pub fn key_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.key_alg)
    }

    /// Name of the signature algorithm.
    #[must_use]
    pub fn sig_alg(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.sig_alg)
    }

    /// OID of the signature algorithm.
    #[must_use]
    pub fn sig_alg_oid(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.sig_alg_oid)
    }

    /// `NotBefore` validity.
    #[must_use]
    pub fn not_before(&self) -> i64 {
        self.0.not_before
    }

    /// `NotAfter` validity.
    #[must_use]
    pub fn not_after(&self) -> i64 {
        self.0.not_after
    }

    /// PEM encoded public key.
    #[must_use]
    pub fn key(&self) -> Option<&[u8]> {
        cstr_ptr_to_slice(&self.0.key)
    }

    /// Parsed X509 Attributes of Issuer.
    #[must_use]
    pub fn issuer_attrs(&self) -> Attributes {
        Attributes(&self.0.issuer_attrs)
    }

    /// Parsed X509 Attributes of Subject.
    #[must_use]
    pub fn subject_attrs(&self) -> Attributes {
        Attributes(&self.0.subject_attrs)
    }
}

/// Various X509 attributes parsed out in raw bytes.
pub struct Attributes<'a>(&'a sys::Attributes);

impl Attributes<'_> {
    /// Country
    #[must_use]
    pub fn country(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.country)
    }

    /// Organization
    #[must_use]
    pub fn organization(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.organization)
    }

    /// Organizational unit
    #[must_use]
    pub fn organizational_unit(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.organizationalUnit)
    }

    /// Name qualifier
    #[must_use]
    pub fn name_qualifier(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.nameQualifier)
    }

    /// State
    #[must_use]
    pub fn state(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.state)
    }

    /// Common name
    #[must_use]
    pub fn common_name(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.commonName)
    }

    /// Serial number
    #[must_use]
    pub fn serial_number(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.serialNumber)
    }

    /// Locality
    #[must_use]
    pub fn locality(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.locality)
    }

    /// Title
    #[must_use]
    pub fn title(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.title)
    }

    /// Surname
    #[must_use]
    pub fn surname(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.surname)
    }

    /// Given name
    #[must_use]
    pub fn given_name(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.givenName)
    }

    /// Initials
    #[must_use]
    pub fn initials(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.initials)
    }

    /// Pseudonym
    #[must_use]
    pub fn pseudonym(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.pseudonym)
    }

    /// Generation qualifier
    #[must_use]
    pub fn generation_qualifier(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.generationQualifier)
    }

    /// Email address
    #[must_use]
    pub fn email_address(&self) -> Option<&[u8]> {
        byte_array_to_slice(&self.0.emailAddress)
    }
}

fn byte_array_to_slice(digest: &sys::ByteArray) -> Option<&[u8]> {
    if digest.data.is_null() {
        None
    } else {
        let len = if digest.len <= 0 {
            0
        } else {
            match usize::try_from(digest.len) {
                Ok(v) => v,
                Err(_) => usize::MAX,
            }
        };
        Some(unsafe { std::slice::from_raw_parts(digest.data, len) })
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

/// Status of verification for a counter signature.
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

/// Status of verification for an authenticode signature.
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
