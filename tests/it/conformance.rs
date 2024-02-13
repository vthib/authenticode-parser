// Tests copied from the authenticode-parser repository.

// Tests must be run with --test-threads=1, as the initialize call might race between tests.

use authenticode_parser::{AuthenticodeVerify, CounterSignatureVerify};

use crate::get_init_token;

mod sys {
    pub enum BioMethod {}
    pub enum Bio {}

    extern "C" {
        pub fn BIO_s_mem() -> *const BioMethod;
        pub fn BIO_new(ty: *const BioMethod) -> *const Bio;

        pub fn BIO_write(b: *const Bio, data: *const u8, len: std::ffi::c_int);

        pub fn BIO_free_all(a: *const Bio);

        pub fn PEM_read_bio(
            bp: *const Bio,
            name: *mut *const i8,
            header: *mut *const i8,
            data: *mut *const u8,
            len: *mut std::ffi::c_long,
        ) -> i32;
    }
}

fn get_test_data(path: &str) -> Vec<u8> {
    use sys::*;

    unsafe {
        let bio = BIO_new(BIO_s_mem());
        let data = std::fs::read(path).unwrap();
        BIO_write(bio, data.as_ptr(), data.len() as _);
        let mut name = std::ptr::null();
        let mut header = std::ptr::null();
        let mut data = std::ptr::null();
        let mut data_len = 0;
        PEM_read_bio(bio, &mut name, &mut header, &mut data, &mut data_len);
        BIO_free_all(bio);
        std::slice::from_raw_parts(data, data_len as _).to_vec()
    }
}

#[test]
fn first_signature_content() {
    let data = get_test_data("tests/assets/sig.pem");
    let token = get_init_token();
    let auth = authenticode_parser::parse(&token, &data).unwrap();

    let signatures = auth.signatures();

    //***********************************//
    // Check the first signature content //
    let first_sig = &signatures[0];
    assert_eq!(first_sig.version(), 1);

    assert_eq!(
        first_sig.digest().unwrap(),
        [
            0xfb, 0xf0, 0x17, 0xe2, 0x1d, 0x7b, 0xe9, 0x8d, 0xee, 0x4a, 0x29, 0xe8, 0xf2, 0x9f,
            0x05, 0xe5, 0xa4, 0x3b, 0x16, 0x9f
        ]
    );
    assert_eq!(first_sig.digest_alg().unwrap(), b"sha1");

    assert_eq!(first_sig.verify_flags(), Some(AuthenticodeVerify::Valid));

    //****************************//
    // Check SignerInfo structure //
    let signer = first_sig.signer().unwrap();
    assert_eq!(signer.digest_alg().unwrap(), b"sha1");

    assert_eq!(
        signer.digest().unwrap(),
        [
            0x26, 0x74, 0x14, 0x28, 0x0c, 0xa4, 0x8e, 0xa7, 0xa6, 0xff, 0x1c, 0x67, 0xf3, 0x71,
            0x32, 0x6d, 0x58, 0xe1, 0xe9, 0x60
        ]
    );
    assert!(signer.program_name().is_none());

    //******************************************//
    // Test all certificates of first signature //
    let certs = first_sig.certs();
    assert_eq!(certs.len(), 4);

    //**************************//
    // Check the 1. certificate //
    let cert = &certs[0];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x6c, 0x07, 0x45, 0x3f, 0xfd, 0xda, 0x08, 0xb8, 0x37, 0x07, 0xc0, 0x9b, 0x82, 0xfb,
            0x3d, 0x15, 0xf3, 0x53, 0x36, 0xb1
        ]
    );

    assert_eq!(
        cert.sha256().unwrap(),
        [
            0x06, 0x25, 0xfe, 0xe1, 0xa8, 0x0d, 0x7b, 0x89, 0x7a, 0x97, 0x12, 0x24, 0x9c, 0x2f,
            0x55, 0xff, 0x39, 0x1d, 0x66, 0x61, 0xdb, 0xd8, 0xb8, 0x7f, 0x9b, 0xe6, 0xf2, 0x52,
            0xd8, 0x8c, 0xed, 0x95
        ]
    );

    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.subject().unwrap(),
        b"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2"
    );
    assert_eq!(
        cert.issuer().unwrap(),
        b"/C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte \
        Timestamping CA"
    );
    assert_eq!(cert.not_after(), 1609372799);
    assert_eq!(cert.not_before(), 1356048000);
    assert_eq!(
        cert.key().unwrap(),
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsayzSVRLlxwSCtgleZEiVypv3LgmxENza8K/\
        LlBa+xTCdo5DASVDtKHiRfTot3vDdMwi17SUAAL3Te2/\
        tLdEJGvNX0U70UTOQxJzF4KLabQry5kerHIbJk1xH7Ex3ftRYQJTpqr1SSwFeEWlL4nO55nn/\
        oziVz89xpLcSvh7M+R5CvvwdYhBnP/\
        FA1GZqtdsn5Nph2Upg4XCYBTEyMk7FNrAgfAfDXTekiKryvf7dHwn5vdKG3+\
        nw54trorqpuaqJxZ9YfeYcRG84lChS+Vd+uUOpyyfqmUg09iW6Mh8pU5IRP8Z4kQHkgvXaISAXWp4ZEXNYEZ+\
        VMETfMV58cnBcQIDAQAB"
    );
    assert_eq!(
        cert.serial().unwrap(),
        b"7e:93:eb:fb:7c:c6:4e:59:ea:4b:9a:77:d4:06:fc:3b"
    );
    assert_eq!(cert.sig_alg().unwrap(), b"sha1WithRSAEncryption");
    assert_eq!(cert.sig_alg_oid().unwrap(), b"1.2.840.113549.1.1.5");
    assert_eq!(cert.key_alg().unwrap(), b"rsaEncryption");

    //**************************//
    // Check the 2. certificate //
    let cert = &certs[1];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x65, 0x43, 0x99, 0x29, 0xb6, 0x79, 0x73, 0xeb, 0x19, 0x2d, 0x6f, 0xf2, 0x43, 0xe6,
            0x76, 0x7a, 0xdf, 0x08, 0x34, 0xe4
        ]
    );

    assert_eq!(
        cert.sha256().unwrap(),
        [
            0x03, 0x74, 0x88, 0x1c, 0x9b, 0x74, 0xd3, 0x1f, 0x28, 0xdc, 0x58, 0x0b, 0x0f, 0x2b,
            0x9d, 0x2b, 0x14, 0xa9, 0x7c, 0xe3, 0x1c, 0xbe, 0xc2, 0xa0, 0x5a, 0xeb, 0x37, 0x7d,
            0xcd, 0xdc, 0xc2, 0xb0
        ]
    );

    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.subject().unwrap(),
        b"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services Signer - G4"
    );
    assert_eq!(
        cert.issuer().unwrap(),
        b"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2"
    );
    assert_eq!(cert.not_after(), 1609286399);
    assert_eq!(cert.not_before(), 1350518400);
    assert_eq!(
        cert.key().unwrap(),
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5OwmNutLA9KxW7/\
        hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0jkBP7oU4uRHFI/\
        JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfultthO0VRHc8SVguSR/\
        yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqhd5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsy\
        i1aLM73ZY8hJnTrFxeozC9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB"
    );
    assert_eq!(
        cert.serial().unwrap(),
        b"0e:cf:f4:38:c8:fe:bf:35:6e:04:d8:6a:98:1b:1a:50"
    );
    assert_eq!(cert.sig_alg().unwrap(), b"sha1WithRSAEncryption");
    assert_eq!(cert.sig_alg_oid().unwrap(), b"1.2.840.113549.1.1.5");
    assert_eq!(cert.key_alg().unwrap(), b"rsaEncryption");

    //**************************//
    // Check the 3. certificate //
    let cert = &certs[2];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x33, 0xe2, 0x4f, 0xe6, 0x6e, 0x01, 0x17, 0xfd, 0xd4, 0x27, 0x86, 0x99, 0xad, 0x42,
            0x3e, 0xf2, 0x66, 0x9f, 0xd2, 0x58
        ]
    );

    assert_eq!(
        cert.sha256().unwrap(),
        [
            0x51, 0xb4, 0xb0, 0xdf, 0x44, 0xa7, 0x40, 0xbc, 0x08, 0x88, 0x17, 0x8c, 0xbe, 0xac,
            0xe8, 0x31, 0x08, 0xa2, 0x49, 0x9e, 0xc2, 0x2f, 0x39, 0x53, 0x89, 0xa9, 0xd7, 0xc6,
            0xab, 0x31, 0xbc, 0x42
        ]
    );

    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.subject().unwrap(),
        b"/C=US/ST=New York/L=New York/O=Slimware Utilities Holdings, Inc./CN=Slimware Utilities \
        Holdings, Inc."
    );
    assert_eq!(
        cert.issuer().unwrap(),
        b"/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=Terms of use at \
        https://www.verisign.com/rpa (c)10/CN=VeriSign Class 3 Code Signing 2010 CA"
    );
    assert_eq!(cert.not_after(), 1546905599);
    assert_eq!(cert.not_before(), 1513123200);
    assert_eq!(
        cert.key().unwrap(),
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArkSLGMoBwKcg6EAppcjBQKHB2cOrlhmGjxdVSCVE+\
        zOHHWVEx+5YP9KYiqShQ2ZPLw2SI9duq2ikRsShHboPgi6SfDb4OU44lsBP/H/\
        sV9OrH2gaDi9IwN+XGzjKbOeIZ828m2GEf/t+kvoRmlxT0ivfiwzolsGqWsp3ELPrI/\
        f+sVMFWrvPZPBGteH67qS+lwq5+4SX7DYJf2NPcJh9o+kYtU6FsY6MWe5oJSr3rhcTqknPhm8BYIKR/\
        fRyjR+\
        P2VYlUoytqjbM7QSACfMsa1Z6OZTMFEJV2iw7V14cyLNptCAU0w1mNtFD7RFYQKzjwkwPUm8dvBvaWSsSgqokZQIDA\
        QAB"
    );
    assert_eq!(
        cert.serial().unwrap(),
        b"30:63:b3:a7:40:c1:cd:fd:f8:bb:9e:6c:33:1a:d7:de"
    );
    assert_eq!(cert.sig_alg().unwrap(), b"sha1WithRSAEncryption");
    assert_eq!(cert.sig_alg_oid().unwrap(), b"1.2.840.113549.1.1.5");
    assert_eq!(cert.key_alg().unwrap(), b"rsaEncryption");

    //**************************//
    // Check the 4. certificate //
    let cert = &certs[3];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x49, 0x58, 0x47, 0xa9, 0x31, 0x87, 0xcf, 0xb8, 0xc7, 0x1f, 0x84, 0x0c, 0xb7, 0xb4,
            0x14, 0x97, 0xad, 0x95, 0xc6, 0x4f
        ]
    );

    assert_eq!(
        cert.sha256().unwrap(),
        [
            0x0c, 0xfc, 0x19, 0xdb, 0x68, 0x1b, 0x01, 0x4b, 0xfe, 0x3f, 0x23, 0xcb, 0x3a, 0x78,
            0xb6, 0x72, 0x08, 0xb4, 0xe3, 0xd8, 0xd7, 0xb6, 0xa7, 0xb1, 0x80, 0x7f, 0x7c, 0xd6,
            0xec, 0xb2, 0xa5, 0x4e
        ]
    );

    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.subject().unwrap(),
        b"/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=Terms of use at \
        https://www.verisign.com/rpa (c)10/CN=VeriSign Class 3 Code Signing 2010 CA"
    );
    assert_eq!(
        cert.issuer().unwrap(),
        b"/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=(c) 2006 VeriSign, Inc. - For \
        authorized use only/CN=VeriSign Class 3 Public Primary Certification Authority - G5"
    );
    assert_eq!(cert.not_after(), 1581119999);
    assert_eq!(cert.not_before(), 1265587200);
    assert_eq!(
        cert.key().unwrap(),
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9SNLXqXXirsy6dRX9+/kxyZ+rRmY/\
        qidfZT2NmsQ13WBMH8EaH/LK3UezR0IjN9plKc3o5x7gOCZ4e43TV/\
        OOxTuhtTQ9Sc1vCULOKeMY50Xowilq7D7zWpigkzVIdob2fHjhDuKKk+FW5ABT8mndhB/\
        JwN8vq5+fcHd+QW8G0icaefApDw8QQA+35blxeSUcdZVAccAJkpAPLWhJqkMp22AjpAle8+/\
        PxzrL5b65Yd3xrVWsno7VDBTG99iNP8e0fRakyiF5UwXTn5b/aSTmX/fze+kde/vFfZH5/\
        gZctguNBqmtKdMfr27Tww9V/Ew1qY2jtaAdtcZLqXNfjQtiQIDAQAB"
    );

    assert_eq!(
        cert.serial().unwrap(),
        b"52:00:e5:aa:25:56:fc:1a:86:ed:96:c9:d4:4b:33:c7"
    );
    assert_eq!(cert.sig_alg().unwrap(), b"sha1WithRSAEncryption");
    assert_eq!(cert.sig_alg_oid().unwrap(), b"1.2.840.113549.1.1.5");
    assert_eq!(cert.key_alg().unwrap(), b"rsaEncryption");

    //*******************************************//
    // Test the first signature countersignature //
    let countersigs = first_sig.countersigs();
    assert_eq!(countersigs.len(), 1);

    let countersig = &countersigs[0];

    assert_eq!(
        countersig.verify_flags(),
        Some(CounterSignatureVerify::Valid)
    );
    assert_eq!(countersig.digest_alg().unwrap(), b"sha1");
    assert_eq!(countersig.sign_time(), 1527779084);
    assert_eq!(
        countersig.digest().unwrap(),
        [
            0xe0, 0x11, 0x73, 0x6f, 0xf0, 0x95, 0x6e, 0x4f, 0x97, 0xd3, 0x81, 0xc0, 0xd9, 0x8d,
            0x46, 0x1d, 0xc2, 0x94, 0x69, 0x1b
        ]
    );

    let chain = countersig.certificate_chain();
    assert_eq!(chain.len(), 2);

    //**************************//
    // Check the 1. certificate //
    let cert = &chain[0];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x65, 0x43, 0x99, 0x29, 0xb6, 0x79, 0x73, 0xeb, 0x19, 0x2d, 0x6f, 0xf2, 0x43, 0xe6,
            0x76, 0x7a, 0xdf, 0x08, 0x34, 0xe4
        ]
    );

    assert_eq!(
        cert.sha256().unwrap(),
        [
            0x03, 0x74, 0x88, 0x1c, 0x9b, 0x74, 0xd3, 0x1f, 0x28, 0xdc, 0x58, 0x0b, 0x0f, 0x2b,
            0x9d, 0x2b, 0x14, 0xa9, 0x7c, 0xe3, 0x1c, 0xbe, 0xc2, 0xa0, 0x5a, 0xeb, 0x37, 0x7d,
            0xcd, 0xdc, 0xc2, 0xb0
        ]
    );

    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.subject().unwrap(),
        b"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services Signer - G4"
    );
    assert_eq!(
        cert.issuer().unwrap(),
        b"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2"
    );
    assert_eq!(cert.not_after(), 1609286399);
    assert_eq!(cert.not_before(), 1350518400);
    assert_eq!(
        cert.key().unwrap(),
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5OwmNutLA9KxW7/\
        hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0jkBP7oU4uRHFI/\
        JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfultthO0VRHc8SVguSR/\
        yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqhd5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsy\
        i1aLM73ZY8hJnTrFxeozC9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB"
    );
    assert_eq!(
        cert.serial().unwrap(),
        b"0e:cf:f4:38:c8:fe:bf:35:6e:04:d8:6a:98:1b:1a:50"
    );
    assert_eq!(cert.sig_alg().unwrap(), b"sha1WithRSAEncryption");
    assert_eq!(cert.sig_alg_oid().unwrap(), b"1.2.840.113549.1.1.5");
    assert_eq!(cert.key_alg().unwrap(), b"rsaEncryption");

    //**************************//
    // Check the 2. certificate //
    let cert = &chain[1];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x6c, 0x07, 0x45, 0x3f, 0xfd, 0xda, 0x08, 0xb8, 0x37, 0x07, 0xc0, 0x9b, 0x82, 0xfb,
            0x3d, 0x15, 0xf3, 0x53, 0x36, 0xb1
        ]
    );

    assert_eq!(
        cert.sha256().unwrap(),
        [
            0x06, 0x25, 0xfe, 0xe1, 0xa8, 0x0d, 0x7b, 0x89, 0x7a, 0x97, 0x12, 0x24, 0x9c, 0x2f,
            0x55, 0xff, 0x39, 0x1d, 0x66, 0x61, 0xdb, 0xd8, 0xb8, 0x7f, 0x9b, 0xe6, 0xf2, 0x52,
            0xd8, 0x8c, 0xed, 0x95
        ]
    );

    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.subject().unwrap(),
        b"/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2"
    );
    assert_eq!(
        cert.issuer().unwrap(),
        b"/C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte \
        Timestamping CA"
    );
    assert_eq!(cert.not_after(), 1609372799);
    assert_eq!(cert.not_before(), 1356048000);
    assert_eq!(
        cert.key().unwrap(),
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsayzSVRLlxwSCtgleZEiVypv3LgmxENza8K/\
        LlBa+xTCdo5DASVDtKHiRfTot3vDdMwi17SUAAL3Te2/\
        tLdEJGvNX0U70UTOQxJzF4KLabQry5kerHIbJk1xH7Ex3ftRYQJTpqr1SSwFeEWlL4nO55nn/\
        oziVz89xpLcSvh7M+R5CvvwdYhBnP/\
        FA1GZqtdsn5Nph2Upg4XCYBTEyMk7FNrAgfAfDXTekiKryvf7dHwn5vdKG3+\
        nw54trorqpuaqJxZ9YfeYcRG84lChS+Vd+uUOpyyfqmUg09iW6Mh8pU5IRP8Z4kQHkgvXaISAXWp4ZEXNYEZ+\
        VMETfMV58cnBcQIDAQAB"
    );
    assert_eq!(
        cert.serial().unwrap(),
        b"7e:93:eb:fb:7c:c6:4e:59:ea:4b:9a:77:d4:06:fc:3b"
    );
    assert_eq!(cert.sig_alg().unwrap(), b"sha1WithRSAEncryption");
    assert_eq!(cert.sig_alg_oid().unwrap(), b"1.2.840.113549.1.1.5");
    assert_eq!(cert.key_alg().unwrap(), b"rsaEncryption");
}

#[test]
fn pe_file() {
    let data = std::fs::read("tests/assets/pe_file").unwrap();
    let token = get_init_token();
    let auth = authenticode_parser::parse_pe(&token, &data).unwrap();
    let signatures = auth.signatures();
    assert_eq!(signatures.len(), 2);

    let sig = &signatures[0];
    {
        assert_eq!(
            sig.verify_flags(),
            Some(AuthenticodeVerify::WrongFileDigest)
        );
        assert_eq!(sig.digest().unwrap().len(), 20);
        assert_eq!(sig.digest_alg().unwrap(), b"sha1");

        let certs = sig.certs();
        assert_eq!(certs[0].sig_alg_oid().unwrap(), b"1.2.840.113549.1.1.5");
        assert_eq!(certs[0].sig_alg().unwrap(), b"sha1WithRSAEncryption");

        assert_eq!(
            sig.digest().unwrap(),
            [
                0xD6, 0x43, 0x40, 0x50, 0x56, 0xA4, 0xA1, 0x60, 0x42, 0xD4, 0x79, 0x42, 0xA8, 0xC6,
                0xA5, 0x95, 0x24, 0xBD, 0xA6, 0x4A
            ]
        );

        assert_eq!(
            sig.file_digest().unwrap(),
            [
                0x9a, 0xd3, 0x54, 0xc6, 0xd1, 0xd3, 0xe5, 0xe5, 0x8b, 0xc4, 0x7e, 0x1c, 0xd3, 0x80,
                0xd1, 0x2b, 0x75, 0xe5, 0x05, 0x1c
            ]
        );
    }

    let sig = &signatures[1];
    {
        assert_eq!(
            sig.verify_flags(),
            Some(AuthenticodeVerify::WrongFileDigest)
        );
        let certs = sig.certs();
        assert_eq!(certs[0].sig_alg_oid().unwrap(), b"1.2.840.113549.1.1.5");
        assert_eq!(certs[0].sig_alg().unwrap(), b"sha1WithRSAEncryption");

        assert_eq!(
            sig.digest().unwrap(),
            [
                0x75, 0xCA, 0xCD, 0xF5, 0xBE, 0x7B, 0xAE, 0xEC, 0xB8, 0x9C, 0x70, 0xBC, 0x01, 0x34,
                0x3F, 0xB7, 0xC9, 0xE8, 0xFD, 0x00, 0x0C, 0xC1, 0x91, 0xF0, 0x8D, 0x2A, 0x99, 0x63,
                0x59, 0xD6, 0x17, 0xFE
            ]
        );

        assert_eq!(
            sig.file_digest().unwrap(),
            [
                0x29, 0xc3, 0x24, 0xac, 0xc3, 0xbd, 0x59, 0x6c, 0xce, 0xbd, 0x28, 0xe7, 0xd8, 0xa8,
                0x8b, 0x87, 0xb0, 0x6a, 0x87, 0xf2, 0xfd, 0x1f, 0xc2, 0x81, 0x52, 0x5c, 0xe0, 0xda,
                0xe4, 0x2b, 0x46, 0xb3
            ]
        );
    }
}

#[test]
fn microsoft_first_signature_content() {
    let data = get_test_data("tests/assets/microsoft.pem");
    let token = get_init_token();
    let auth = authenticode_parser::parse(&token, &data).unwrap();

    let signatures = auth.signatures();

    //***********************************//
    // Check the first signature content //
    let first_sig = &signatures[0];
    assert_eq!(first_sig.version(), 1);

    assert_eq!(
        first_sig.digest().unwrap(),
        [
            0xc7, 0xfe, 0xf9, 0x4e, 0x32, 0x9b, 0xd9, 0xb6, 0x6b, 0x28, 0x15, 0x39, 0x26, 0x5f,
            0x98, 0x93, 0x13, 0x35, 0x6c, 0xbd, 0x9c, 0x34, 0x5d, 0xf9, 0xe6, 0x70, 0xe9, 0xc4,
            0xb6, 0xe0, 0xed, 0xce
        ]
    );
    assert_eq!(first_sig.digest_alg().unwrap(), b"sha256");

    assert_eq!(first_sig.verify_flags(), Some(AuthenticodeVerify::Valid));

    //****************************//
    // Check SignerInfo structure //
    let signer = first_sig.signer().unwrap();
    assert_eq!(signer.digest_alg().unwrap(), b"sha256");

    assert_eq!(
        signer.digest().unwrap(),
        [
            0x16, 0xef, 0xc5, 0x25, 0x0c, 0x4d, 0x4a, 0x99, 0xa0, 0x0e, 0xd2, 0xad, 0x9a, 0x0e,
            0x3d, 0x8f, 0xbc, 0x21, 0xda, 0x5b, 0xe9, 0x5a, 0xc3, 0x5a, 0xd3, 0x3b, 0x3d, 0x9c,
            0x3f, 0x37, 0x19, 0xa1
        ]
    );
    assert_eq!(signer.program_name().unwrap(), b"Procexp");

    //******************************************//
    // Test all certificates of first signature //
    let certs = first_sig.certs();
    assert_eq!(certs.len(), 4);

    //**************************//
    // Check the 1. certificate //
    let cert = &certs[0];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x92, 0xd7, 0x19, 0x2a, 0x7c, 0x31, 0x80, 0x91, 0x2f, 0xf8, 0x41, 0x4f, 0x79, 0x09,
            0x73, 0xa0, 0x5c, 0x28, 0xf8, 0xb0
        ]
    );

    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.subject().unwrap(),
        b"/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Hardware \
        Compatibility Publisher"
    );
    assert_eq!(
        cert.issuer().unwrap(),
        b"/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Third Party \
        Component CA 2012"
    );

    //**************************//
    // Check the 2. certificate //
    let cert = &certs[1];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x77, 0xa1, 0x0e, 0xbf, 0x07, 0x54, 0x27, 0x25, 0x21, 0x8c, 0xd8, 0x3a, 0x01, 0xb5,
            0x21, 0xc5, 0x7b, 0xc6, 0x7f, 0x73
        ]
    );

    //**************************//
    // Check the 3. certificate //
    let cert = &certs[2];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x9a, 0xb3, 0xfa, 0x0a, 0x1a, 0xdb, 0xcf, 0x46, 0xb1, 0xee, 0xce, 0x7b, 0x9f, 0x93,
            0xe8, 0xa7, 0x75, 0x42, 0xf2, 0x0c
        ]
    );

    //**************************//
    // Check the 4. certificate //
    let cert = &certs[3];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x2a, 0xa7, 0x52, 0xfe, 0x64, 0xc4, 0x9a, 0xbe, 0x82, 0x91, 0x3c, 0x46, 0x35, 0x29,
            0xcf, 0x10, 0xff, 0x2f, 0x04, 0xee
        ]
    );

    //*******************************************//
    // Check the Counter signature //
    let countersigs = first_sig.countersigs();
    assert_eq!(countersigs.len(), 1);

    let countersig = &countersigs[0];

    assert_eq!(
        countersig.verify_flags(),
        Some(CounterSignatureVerify::Valid)
    );
    assert_eq!(countersig.digest_alg().unwrap(), b"sha256");
    assert_eq!(countersig.sign_time(), 1629165693);
    assert_eq!(
        countersig.digest().unwrap(),
        [
            0xed, 0xdf, 0x8a, 0x45, 0x34, 0x0e, 0x16, 0xb3, 0x55, 0x6a, 0x8e, 0x52, 0xb3, 0xfc,
            0xd2, 0xe7, 0x3c, 0x5c, 0x47, 0xd3, 0x6a, 0xa6, 0x71, 0x4f, 0xfe, 0xef, 0x2c, 0x19,
            0x60, 0x37, 0x67, 0x6f
        ]
    );

    let chain = countersig.certificate_chain();
    assert_eq!(chain.len(), 2);

    //**************************//
    // Check the 1. certificate //
    let cert = &chain[0];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x9a, 0xb3, 0xfa, 0x0a, 0x1a, 0xdb, 0xcf, 0x46, 0xb1, 0xee, 0xce, 0x7b, 0x9f, 0x93,
            0xe8, 0xa7, 0x75, 0x42, 0xf2, 0x0c
        ]
    );

    assert_eq!(
        cert.sha256().unwrap(),
        [
            0x8a, 0xaa, 0x18, 0x95, 0xfb, 0x3c, 0x0d, 0x0e, 0xba, 0x54, 0xec, 0x34, 0x41, 0xec,
            0xc8, 0xb9, 0xef, 0x18, 0xba, 0x18, 0x13, 0x58, 0xb0, 0x68, 0xe0, 0x66, 0xaa, 0xb6,
            0xa9, 0x53, 0x0a, 0x32
        ]
    );

    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.subject().unwrap(),
        b"/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/OU=Microsoft Operations Puerto \
        Rico/OU=Thales TSS ESN:32BD-E3D5-3B1D/CN=Microsoft Time-Stamp Service"
    );
    assert_eq!(
        cert.issuer().unwrap(),
        b"/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Time-Stamp PCA 2010"
    );
    assert_eq!(cert.not_after(), 1649703742);
    assert_eq!(cert.not_before(), 1610650942);
    assert_eq!(
        cert.key().unwrap(),
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA74ah1Pa5wvcyvYNCy/\
        YQs1tK8rIGlh1Qq1QFaJmYVXLXykb+m5yCStzmL227wJjsalZX8JA2YcbaZV5Icwm9vAJz8AC/sk/\
        dsUK3pmDvkhtVI04YDV6otuZCILpQB9Ipcs3d0e1Dl2KKFvdibOk0/0rRxU9l+/\
        Yxeb5lVTRERLxzI+Rd6Xv5QQYT6Sp2IE0N1vzIFd3yyO773T5XifNgL5lZbtIUnYUVmUBKlVoemO/\
        54aiFeVBpIG+\
        YzhDTF7cuHNAzxWIbP1wt4VIqAV9JjuqLMvvBSD56pi8NTKM9fxrERAeaTS2HbfBYfmnRZ27Czjeo0ijQ5DSZGi0Er\
        vWfKQIDAQAB"
    );
    assert_eq!(
        cert.serial().unwrap(),
        b"33:00:00:01:62:d0:fe:02:f3:01:e5:cd:49:00:00:00:00:01:62"
    );
    assert_eq!(cert.sig_alg().unwrap(), b"sha256WithRSAEncryption");
    assert_eq!(cert.key_alg().unwrap(), b"rsaEncryption");

    //**************************//
    // Check the 2. certificate //
    let cert = &chain[1];
    assert_eq!(
        cert.sha1().unwrap(),
        [
            0x2a, 0xa7, 0x52, 0xfe, 0x64, 0xc4, 0x9a, 0xbe, 0x82, 0x91, 0x3c, 0x46, 0x35, 0x29,
            0xcf, 0x10, 0xff, 0x2f, 0x04, 0xee
        ]
    );

    assert_eq!(
        cert.sha256().unwrap(),
        [
            0x86, 0xec, 0x11, 0x8d, 0x1e, 0xe6, 0x96, 0x70, 0xa4, 0x6e, 0x2b, 0xe2, 0x9c, 0x4b,
            0x42, 0x08, 0xbe, 0x04, 0x3e, 0x36, 0x60, 0x0d, 0x4e, 0x1d, 0xd3, 0xf3, 0xd5, 0x15,
            0xca, 0x11, 0x90, 0x20
        ]
    );

    assert_eq!(cert.version(), 2);
    assert_eq!(
        cert.subject().unwrap(),
        b"/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Time-Stamp PCA 2010"
    );
    assert_eq!(
        cert.issuer().unwrap(),
        b"/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Root Certificate \
        Authority 2010"
    );
    assert_eq!(cert.not_after(), 1751406415);
    assert_eq!(cert.not_before(), 1278020215);
    assert_eq!(
        cert.key().unwrap(),
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/\
        X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/\
        FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+\
        TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/\
        9WbAA5ZEfu/QS/\
        1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQAB"
    );
    assert_eq!(cert.serial().unwrap(), b"61:09:81:2a:00:00:00:00:00:02");
    assert_eq!(cert.sig_alg().unwrap(), b"sha256WithRSAEncryption");
    assert_eq!(cert.key_alg().unwrap(), b"rsaEncryption");
}
