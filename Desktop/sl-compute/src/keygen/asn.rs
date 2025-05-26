use asn1::{parse, BigUint, BitString, ObjectIdentifier, ParseResult, Sequence};

#[allow(clippy::result_large_err)]
pub fn parse_asn1_public_key(data: &[u8]) -> ParseResult<([u8; 32], [u8; 32])> {
    parse(data, |data| {
        // Outer SEQUENCE
        data.read_element::<Sequence>()?
            .parse(|data| -> Result<([u8; 32], [u8; 32]), _> {
                // Inner SEQUENCE
                data.read_element::<Sequence>()?.parse(|data| {
                    // OBJECT IDENTIFIER (ecPublicKey)
                    let oid1 = data.read_element::<ObjectIdentifier>()?;
                    assert_eq!(oid1.to_string(), "1.2.840.10045.2.1");

                    // SEQUENCE containing version, curve OID, etc.
                    data.read_element::<Sequence>()?.parse(|data| {
                        // INTEGER (version)
                        let _version = data.read_element::<BigUint>()?;
                        // assert_eq!(version, BigUint::one());

                        // SEQUENCE for curve details
                        data.read_element::<Sequence>()?.parse(|data| {
                            // OBJECT IDENTIFIER for curve
                            let curve_oid = data.read_element::<ObjectIdentifier>()?;
                            assert_eq!(curve_oid.to_string(), "1.2.840.10045.1.1");

                            // INTEGER (curve prime)
                            let _prime = data.read_element::<BigUint>()?;

                            Ok(())
                        })?;

                        // SEQUENCE for generator
                        data.read_element::<Sequence>()?.parse(|data| {
                            // OCTETSTRING for X
                            let _gen_x = data.read_element::<&[u8]>()?;

                            // OCTETSTRING for Y
                            let _gen_y = data.read_element::<&[u8]>()?;
                            Ok(())
                        })?;

                        // OCTETSTRING for public key
                        let _public_key = data.read_element::<&[u8]>()?;

                        // INTEGER (order of the group)
                        let _group_order = data.read_element::<BigUint>()?;

                        // INTEGER (cofactor)
                        let _cofactor = data.read_element::<BigUint>()?;

                        Ok(())
                    })?;

                    Ok(())
                })?;

                // BITSTRING for EC point with 0 unused bits
                let bitstring = data.read_element::<BitString>()?;
                let bitstring_bytes = bitstring.as_bytes();
                let x: [u8; 32] = bitstring_bytes[1..33]
                    .try_into()
                    .expect("conversion failed");
                let y: [u8; 32] = bitstring_bytes[33..].try_into().expect("conversion failed");
                Ok((x, y))
            })
    })
}

#[allow(clippy::result_large_err)]
pub fn parse_asn1_private_key(data: &[u8]) -> ParseResult<[u8; 32]> {
    parse(data, |data| {
        // Outer SEQUENCE
        data.read_element::<Sequence>()?
            .parse(|data| -> Result<[u8; 32], _> {
                // INTEGER (curve prime)
                let _prime = data.read_element::<BigUint>()?;

                // Inner SEQUENCE for public key details
                data.read_element::<Sequence>()?.parse(|data| {
                    // OBJECT IDENTIFIER (ecPublicKey)
                    let oid1 = data.read_element::<ObjectIdentifier>()?;
                    assert_eq!(oid1.to_string(), "1.2.840.10045.2.1");

                    // Next SEQUENCE for curve parameters
                    data.read_element::<Sequence>()?.parse(|data| {
                        // INTEGER (version)
                        let _version = data.read_element::<BigUint>()?;
                        // assert_eq!(version, BigUint::one());

                        // Next SEQUENCE for curve details
                        data.read_element::<Sequence>()?.parse(|data| {
                            // OBJECT IDENTIFIER for curve
                            let curve_oid = data.read_element::<ObjectIdentifier>()?;
                            assert_eq!(curve_oid.to_string(), "1.2.840.10045.1.1");

                            // INTEGER (curve prime)
                            let _prime = data.read_element::<BigUint>()?;
                            Ok(())
                        })?;

                        // SEQUENCE for generator point
                        data.read_element::<Sequence>()?.parse(|data| {
                            // OCTETSTRING for X
                            let _gen_x = data.read_element::<&[u8]>()?;

                            // OCTETSTRING for Y
                            let _gen_y = data.read_element::<&[u8]>()?;
                            Ok(())
                        })?;

                        // Read the remaining fields
                        let _public_key = data.read_element::<&[u8]>()?;
                        let _group_order = data.read_element::<BigUint>()?;
                        let _cofactor = data.read_element::<BigUint>()?;

                        Ok(())
                    })?;

                    Ok(())
                })?;

                // Parse BITSTRING for the EC point
                let bitstring = data.read_element::<&[u8]>()?;
                // let bitstring_bytes = bitstring.as_bytes();
                let x: [u8; 32] = bitstring[9..(32 + 9)]
                    .try_into()
                    .expect("conversion failed");
                // let y: [u8; 32] = bitstring_bytes[33..].try_into().expect("conversion failed");

                Ok(x) // Return the X and Y coordinates
            })
    })
}

#[cfg(test)]
mod tests {
    use base64::{prelude::BASE64_STANDARD, Engine};
    use num_bigint::BigUint;
    use num_traits::FromBytes;

    use crate::keygen::asn::parse_asn1_private_key;

    use super::parse_asn1_public_key;

    #[test]
    fn test_asn_functions() {
        let pubkey = r###"MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAAQkEybsHS1Nu2o/oR14qAykP9jLbyRyTyPXFFRlPW729VF7SdyFX2qfaKG0yvIpEtk2Il7w8ijK5DZ/NI0oLA9q"###;

        let decoded = BASE64_STANDARD.decode(pubkey).unwrap();

        let (x, y) = parse_asn1_public_key(&decoded).unwrap();
        println!("{:?} {:?}", x, y);

        let privkey = r###"MIICRwIBADCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCASCAVMwggFPAgEBBCAGYSoaaBlSf5WyqoI38Yo0pWVfQOpltKhiPpdBeE47GqCB4TCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCKFEA0IABCORVG3u1nNKYFh2TiW+343AWNX2z7tDRmLyHR6wH5B1aDX3aCLEJ8eIjTCEqqinJOm/mUDIOtGSLZ2t/K4fdoo="###;

        let decoded = BASE64_STANDARD.decode(privkey).unwrap();

        let x = parse_asn1_private_key(&decoded).unwrap();
        println!("{:?}", x);

        println!("{}", BigUint::from_be_bytes(&x));
    }
}
