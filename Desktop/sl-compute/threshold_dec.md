# Flow of threshold decryption

## Inputs

* `PuK       = Public Key              = clear`
* `PrK       = Private Key             = secret-shared`
* `RNc       = Remote Nonce            = clear`
* `ONc       = Our Nonce               = clear`
* `C         = Ciphertext              = clear`

## Main Functions

*   ### HKDF
    ```
    test_run_hkdf(
        length: usize,
        input_p1: &mut HkdfPartyInput,
        input_p2: &mut HkdfPartyInput,
        input_p3: &mut HkdfPartyInput,
    ) -> (
        Vec<BinaryShare>, 
        Vec<BinaryShare>, 
        Vec<BinaryShare>
    )
    ```

*   ### XOR Arrays
    ```
    xor_array(
        a: Vec<Binary>, 
        b: Vec<Binary>
    ) -> Vec<Binary>
    ```

*   ### AES GCM Decryption
    ```
    test_run_aes_gcm_encrypt_decrypt(
        ciphertext: &[u8],
        input_p1: &mut AesGcmDecryptPartyInput,
        input_p2: &mut AesGcmDecryptPartyInput,
        input_p3: &mut AesGcmDecryptPartyInput,
    ) -> (
        Vec<BinaryShare>, 
        Vec<BinaryShare>, 
        Vec<BinaryShare>
    )
    ```

* ### EC to Boolean Shares
    ```
    test_run_ec_to_b(
        points_p1: Vec<ArithmeticECShare>, 
        points_p2: Vec<ArithmeticECShare>, 
        points_p3: Vec<ArithmeticECShare>,
        serverstate_p1: &mut ServerState, 
        serverstate_p2: &mut ServerState, 
        serverstate_p3: &mut ServerState
    ) -> (
        BinaryECShareArray, 
        BinaryECShareArray, 
        BinaryECShareArray,
        BinaryECShareArray, 
        BinaryECShareArray, 
        BinaryECShareArray
    )
    ```
*   ### Threshold Scalar Multiplication
    ```
    scalar_mult( 
    Public EC point, 
    Secret-Shared Scalar
    ) -> Secret-Shared SharedKey {
        todo!()
    }
    ```

## Derived Functions

* ### get_session_key
    Used to get the session key from the xored nonces and the shared key
    ```
    def get_session_key(xoredNonce: bytes, sharedKey: bytes):
        salt = b""
        for i in range(20):
            salt += xoredNonce[i].to_bytes(length=1)
        prk = hkdf_extract(salt=salt, input_key_material=sharedKey)
        sessionkey = hkdf_expand(prk=prk, info=b"", length=32)
        return sessionkey
    ```

* ### get_iv
    Used to get the iv from the xored nonces
    ```
    def get_iv(xoredNonce: bytes):
        iv = b""
        for i in range(12):
            iv += xoredNonce[i + 20].to_bytes(length=1)
        return iv
    ```

## Step by Step Procedure

1) ### Get xor of Nonces
    ```
    xorN = xor_array(RNc, ONc)                                    # clear output
    ```

2) ### Get shared key from public and private keys
    ```
    SharedKey = scalar_mult(PuK, PrK)                             # secret-shared output
    ```
    
3) ### Get boolean sharings of the shared key
    ```
    SharedKeyBool = ec_to_b(SharedKey)                        # secret-shared output
    ```

4) ### Get the session key using the xored nonces and the boolean shared key
    ```
    SessionKey = get_session_key(SharedKeyBool, xorN)             # secret-shared output
    ```

5) ### Get the iv from the xored nonces
    ```
    IV = get_iv(xorN)                                             # clear output
    ```

6) ### Get the secret-shared message using threshold decryption
    ```
    M = test_run_aes_gcm_encrypt_decrypt(C, SessionKey, IV)       # clear output
    ```

## Test Run outputs

### Test 1: Basic inputs:
* `SharedKey: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] `
* `ONc: [102, 53, 102, 54, 55, 49, 99, 97, 51, 51, 102, 52, 48, 101, 53, 102, 55, 101, 48, 99, 97, 50, 101, 54, 50, 52, 102, 51, 57, 101, 54, 101] `
* `RNc: [102, 53, 102, 54, 55, 49, 99, 97, 51, 51, 102, 52, 48, 101, 53, 102, 55, 101, 48, 99, 97, 50, 101, 54, 50, 52, 102, 51, 57, 101, 54, 101] `
* `C: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] `
* `xorN: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] `
* `SessionKey: [223, 114, 4, 84, 111, 27, 238, 120, 184, 83, 36, 167, 137, 140, 161, 25, 179, 135, 224, 19, 134, 209, 174, 240, 55, 120, 29, 74, 138, 3, 106, 238] `
* `IV: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] `
* `M: [2, 85, 86, 4, 88, 106, 119, 244, 58, 173, 141, 95, 204, 183, 196, 189, 74, 140, 31, 29, 218, 53, 255, 233, 233, 190, 90, 13, 157, 171, 141, 104] `

### Test 2: Practical inputs:
* `SharedKey: [3, 205, 208, 22, 129, 87, 102, 208, 13, 255, 202, 80, 183, 254, 197, 68, 27, 174, 232, 124, 49, 42, 228, 107, 139, 8, 74, 160, 104, 181, 254, 127] `
* `ONc: [102, 53, 102, 54, 55, 49, 99, 97, 51, 51, 102, 52, 48, 101, 53, 102, 55, 101, 48, 99, 97, 50, 101, 54, 50, 52, 102, 51, 57, 101, 54, 101] `
* `RNc: [223, 114, 4, 84, 111, 27, 238, 120, 184, 83, 36, 167, 137, 140, 161, 25, 179, 135, 224, 19, 134, 209, 174, 240, 55, 120, 29, 74, 138, 3, 106, 238] `
* `xorN: [185, 71, 98, 98, 88, 42, 141, 25, 139, 96, 66, 147, 185, 233, 148, 127, 132, 226, 208, 112, 231, 227, 203, 198, 5, 76, 123, 121, 179, 102, 92, 139] `
* `SessionKey: [232, 245, 33, 234, 177, 220, 157, 109, 183, 139, 94, 210, 120, 151, 208, 82, 195, 107, 216, 105, 63, 89, 42, 47, 125, 184, 57, 28, 188, 231, 2, 68] `
* `IV: [231, 227, 203, 198, 5, 76, 123, 121, 179, 102, 92, 139] `
* `M: [84, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 32, 114, 117, 110, 32, 111, 102, 32, 116, 104, 101, 32, 116, 104, 114, 101, 115, 104, 111, 108, 100, 32, 100, 101, 99, 114, 121, 112, 116, 105, 111, 110] `
* `M decoded using utf-8: This is a test run of the threshold decryption `