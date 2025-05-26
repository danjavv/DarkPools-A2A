use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Deserialize)]
pub struct EncryptionKey {
    #[serde(rename = "KeyMaterial")]
    pub key_material: KeyMaterialGen,
    #[serde(rename = "errorInfo")]
    pub error_info: Option<String>,
    #[serde(rename = "privateKey")]
    pub private_key: String,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct KeyMaterialGen {
    #[serde(rename = "cryptoAlg")]
    pub crypto_alg: String,
    pub curve: String,
    pub params: Option<String>,
    #[serde(rename = "DHPublicKey")]
    pub dhpublic_key: DHPublicKey,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct DHPublicKey {
    pub expiry: String,
    #[serde(rename = "Parameters")]
    pub parameters: Option<String>,
    #[serde(rename = "KeyValue")]
    pub key_value: String,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct RemoteKeyMaterial {
    #[serde(rename = "DHPublicKey")]
    pub dhpublic_key: DHPublicKey,
    #[serde(rename = "cryptoAlg")]
    pub crypto_alg: String,
    pub curve: String,
    pub params: String,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct EncryptionRequest {
    #[serde(rename = "base64RemoteNonce")]
    pub base64_remote_nonce: String,
    #[serde(rename = "base64YourNonce")]
    pub base64_your_nonce: String,
    pub data: String,
    #[serde(rename = "ourPrivateKey")]
    pub our_private_key: String,
    #[serde(rename = "remoteKeyMaterial")]
    pub remote_key_material: RemoteKeyMaterial,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct ErrorInfo {
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
    #[serde(rename = "errorMessage")]
    pub error_message: Option<String>,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct EncryptionResponse {
    #[serde(rename = "base64Data")]
    base64_data: Option<String>,
    #[serde(rename = "errorInfo")]
    error_info: Option<ErrorInfo>,
}

#[cfg(test)]
mod tests {
    use sl_compute::keygen::dkg::test_run_dkg;

    use chrono::{Duration, Utc};
    use reqwest::Client;
    use rust_decimal::Decimal;
    use sl_compute::types::ArithmeticECShare;

    use crate::entire_flow::{
        DHPublicKey, EncryptionRequest, EncryptionResponse, RemoteKeyMaterial,
    };

    use crate::process_plaintext_sh::{
        test_run_get_data_protocol, GetDataPltextInput, TransactionEntry,
    };
    use sl_compute::proto::{
        reconstruct_binary_share, reconstruct_byte_share_to_string, reconstruct_decimal,
    };
    use sl_compute::transport::test_utils::setup_mpc;
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim_get_data<S, R>(
        coord: S,
        sim_params: &[(GetDataPltextInput, ArithmeticECShare); 3],
    ) -> Vec<Vec<TransactionEntry>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_run_get_data_protocol(setup, seed, params, relay));
        }

        let mut results = vec![];
        while let Some(fini) = jset.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            let res = fini.unwrap();
            results.push(res);
        }

        results.sort_by_key(|r| r.0);
        results.into_iter().map(|r| r.1).collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_entire_flow_i() {
        let now = Utc::now();
        let future_time = now + Duration::hours(30);
        let timestamp = future_time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        // let response = reqwest::get("https://rahasya.openbanking.silencelaboratories.com/ecc/v1/generateKey").await.unwrap().text().await.unwrap();
        // let response_json: EncryptionKey = serde_json::from_str(&response).unwrap(); // Parse the response
        // println!("{:?}", response_json)
        // REMOTE NONCE: KqhyUQkmkiy25Hl3WXRh2H8fe8gVpbfBrYR70p6yveE=
        // REMOTE SECRET KEY: -----BEGIN PRIVATE KEY-----MIICRwIBADCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCASCAVMwggFPAgEBBCAIND427PzqSw8bRe4pdtIvEpycM2zENrLpCaDnD/tqdqCB4TCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCKFEA0IABCQTJuwdLU27aj+hHXioDKQ/2MtvJHJPI9cUVGU9bvb1UXtJ3IVfap9oobTK8ikS2TYiXvDyKMrkNn80jSgsD2o=-----END PRIVATE KEY-----
        // REMOTE PUBLIC KEY: -----BEGIN PUBLIC KEY-----MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAAQkEybsHS1Nu2o/oR14qAykP9jLbyRyTyPXFFRlPW729VF7SdyFX2qfaKG0yvIpEtk2Il7w8ijK5DZ/NI0oLA9q-----END PUBLIC KEY-----
        let remote_nonce = "KqhyUQkmkiy25Hl3WXRh2H8fe8gVpbfBrYR70p6yveE=".to_string();
        let remote_public_key = "-----BEGIN PUBLIC KEY-----MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAAQkEybsHS1Nu2o/oR14qAykP9jLbyRyTyPXFFRlPW729VF7SdyFX2qfaKG0yvIpEtk2Il7w8ijK5DZ/NI0oLA9q-----END PUBLIC KEY-----".to_string();
        let remote_secret_key = "-----BEGIN PRIVATE KEY-----MIICRwIBADCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCASCAVMwggFPAgEBBCAIND427PzqSw8bRe4pdtIvEpycM2zENrLpCaDnD/tqdqCB4TCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCKFEA0IABCQTJuwdLU27aj+hHXioDKQ/2MtvJHJPI9cUVGU9bvb1UXtJ3IVfap9oobTK8ikS2TYiXvDyKMrkNn80jSgsD2o=-----END PRIVATE KEY-----".to_string();

        // let input = r###"<Account xmlns="http://api.rebit.org.in/FISchema/deposit" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://api.rebit.org.in/FISchema/deposit ../FISchema/deposit.xsd" linkedAccRef="f5192fed-6c9c-493b-b85d-aa8235c7399c" maskedAccNumber="XXXXXX8988" version="1.2" type="deposit"><Profile><Holders type="SINGLE"><Holder name="YOGESH  MALVIYA" dob="1992-09-04" mobile="9098597913" nominee="NOT-REGISTERED" email="yogzmalviya@gmail.com" pan="ECEPM3212A" ckycCompliance="false" /></Holders></Profile><Summary currentBalance="163.8" currency="INR" exchgeRate="" balanceDateTime="2022-12-14T14:01:16.628+05:30" type="SAVINGS" branch="BHOPAL - ARERA COLONY" facility="CC" ifscCode="KKBK0005886" micrCode="" openingDate="2021-10-13" currentODLimit="0" drawingLimit="163.80" status="ACTIVE"><Pending amount="0.0" /></Summary><Transactions startDate="2022-06-12" endDate="2022-12-14"><Transaction txnId="S25836278" type="DEBIT" mode="OTHERS" amount="400.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:56" reference="216311406416" /><Transaction txnId="S18628747" type="CREDIT" mode="OTHERS" amount="100.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="UPI/YOGESH MALVIYA/216305036794/NA" reference="UPI-216377280207" /><Transaction txnId="S18624783" type="CREDIT" mode="OTHERS" amount="1781.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="UPI/YOGESH MALVIYA/216305030230/NA" reference="UPI-216377277537" /><Transaction txnId="S30323399" type="DEBIT" mode="OTHERS" amount="148.75" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="UPI/RazorpayZomato/216386232803/ZomatoOnlineOrd" reference="UPI-216389748326" /><Transaction txnId="S25864256" type="DEBIT" mode="OTHERS" amount="150.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:58" reference="216311406641" /><Transaction txnId="S31627541" type="DEBIT" mode="OTHERS" amount="1000.0" currentBalance="300.57" transactionTimestamp="2022-06-19T00:00:00+05:30" valueDate="2022-06-19" narration="UPI/Akshay Adlak/217021352961/MB UPI" reference="UPI-217095781141" /></Transactions></Account>"###;
        // let input = r###"<Account xmlns="http://api.rebit.org.in/FISchema/deposit" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://api.rebit.org.in/FISchema/deposit ../FISchema/deposit.xsd" linkedAccRef="f5192fed-6c9c-493b-b85d-aa8235c7399c" maskedAccNumber="XXXXXX8988" version="1.2" type="deposit"><Profile><Holders type="SINGLE"><Holder name="YOGESH  MALVIYA" dob="1992-09-04" mobile="9098597913" nominee="NOT-REGISTERED" email="yogzmalviya@gmail.com" pan="ECEPM3212A" ckycCompliance="false" /></Holders></Profile><Summary currentBalance="163.8" currency="INR" exchgeRate="" balanceDateTime="2022-12-14T14:01:16.628+05:30" type="SAVINGS" branch="BHOPAL - ARERA COLONY" facility="CC" ifscCode="KKBK0005886" micrCode="" openingDate="2021-10-13" currentODLimit="0" drawingLimit="163.80" status="ACTIVE"><Pending amount="0.0" /></Summary><Transactions startDate="2022-06-12" endDate="2022-12-14"><Transaction txnId="S25836278" type="DEBIT" mode="OTHERS" amount="400.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="1PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:56" reference="216311406416" /><Transaction txnId="S18628747" type="CREDIT" mode="OTHERS" amount="100.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="9UPI/YOGESH MALVIYA/216305036794/NA" reference="UPI-216377280207" /><Transaction txnId="S18624783" type="CREDIT" mode="OTHERS" amount="1781.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="9UPI/YOGESH MALVIYA/216305030230/NA" reference="UPI-216377277537" /><Transaction txnId="S30323399" type="DEBIT" mode="OTHERS" amount="148.75" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="2UPI/RazorpayZomato/216386232803/ZomatoOnlineOrd" reference="UPI-216389748326" /><Transaction txnId="S25864256" type="DEBIT" mode="OTHERS" amount="150.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="3PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:58" reference="216311406641" /><Transaction txnId="S42506559" type="DEBIT" mode="OTHERS" amount="19.0" currentBalance="1130.44" transactionTimestamp="2022-06-13T00:00:00+05:30" valueDate="2022-06-13" narration="4UPI/Dheerendra Jain/216464548973/Oid202206131918" reference="UPI-216402403500" /><Transaction txnId="S34780351" type="DEBIT" mode="OTHERS" amount="44.0" currentBalance="1130.44" transactionTimestamp="2022-06-13T00:00:00+05:30" valueDate="2022-06-13" narration="5UPI/Dheerendra Jain/216418410134/Oid202206131028" reference="UPI-216494338490" /><Transaction txnId="S52138551" type="CREDIT" mode="OTHERS" amount="140.0" currentBalance="999.44" transactionTimestamp="2022-06-14T00:00:00+05:30" valueDate="2022-06-14" narration="9UPI/RAKESH KUMAR KH/216513632305/UPI" reference="UPI-216512500252" /><Transaction txnId="S52219985" type="DEBIT" mode="OTHERS" amount="80.0" currentBalance="999.44" transactionTimestamp="2022-06-14T00:00:00+05:30" valueDate="2022-06-14" narration="6UPI/RAJORIYA DK RES/216534278929/Oid202206141402" reference="UPI-216512585462" /><Transaction txnId="S52543272" type="DEBIT" mode="OTHERS" amount="90.0" currentBalance="999.44" transactionTimestamp="2022-06-14T00:00:00+05:30" valueDate="2022-06-14" narration="7UPI/DOLARAJ PANDEY/216535664081/Oid202206141422" reference="UPI-216512923895" /></Transactions></Account>"###;
        let input = r###"<Account xmlns="http://api.rebit.org.in/FISchema/deposit" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://api.rebit.org.in/FISchema/deposit ../FISchema/deposit.xsd" linkedAccRef="f5192fed-6c9c-493b-b85d-aa8235c7399c" maskedAccNumber="XXXXXX8988" version="1.2" type="deposit"><Profile><Holders type="SINGLE"><Holder name="YOGESH  MALVIYA" dob="1992-09-04" mobile="9098597913" nominee="NOT-REGISTERED" email="yogzmalviya@gmail.com" pan="ECEPM3212A" ckycCompliance="false" /></Holders></Profile><Summary currentBalance="163.8" currency="INR" exchgeRate="" balanceDateTime="2022-12-14T14:01:16.628+05:30" type="SAVINGS" branch="BHOPAL - ARERA COLONY" facility="CC" ifscCode="KKBK0005886" micrCode="" openingDate="2021-10-13" currentODLimit="0" drawingLimit="163.80" status="ACTIVE"><Pending amount="0.0" /></Summary><Transactions startDate="2022-06-12" endDate="2022-12-14"><Transaction txnId="S25836278" type="DEBIT" mode="OTHERS" amount="400.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="1PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:56" reference="216311406416" /><Transaction txnId="S18628747" type="CREDIT" mode="OTHERS" amount="100.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="9UPI/YOGESH MALVIYA/216305036794/NA" reference="UPI-216377280207" /><Transaction txnId="S18624783" type="CREDIT" mode="OTHERS" amount="1781.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="9UPI/YOGESH MALVIYA/216305030230/NA" reference="UPI-216377277537" /><Transaction txnId="S30323399" type="DEBIT" mode="OTHERS" amount="148.75" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="2UPI/RazorpayZomato/216386232803/ZomatoOnlineOrd" reference="UPI-216389748326" /><Transaction txnId="S25864256" type="DEBIT" mode="OTHERS" amount="150.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="3PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:58" reference="216311406641" /><Transaction txnId="S42506559" type="DEBIT" mode="OTHERS" amount="19.0" currentBalance="1130.44" transactionTimestamp="2022-06-13T00:00:00+05:30" valueDate="2022-06-13" narration="4UPI/Dheerendra Jain/216464548973/Oid202206131918" reference="UPI-216402403500" /><Transaction txnId="S34780351" type="DEBIT" mode="OTHERS" amount="44.0" currentBalance="1130.44" transactionTimestamp="2022-06-13T00:00:00+05:30" valueDate="2022-06-13" narration="5UPI/Dheerendra Jain/216418410134/Oid202206131028" reference="UPI-216494338490" /><Transaction txnId="S52138551" type="CREDIT" mode="OTHERS" amount="140.0" currentBalance="999.44" transactionTimestamp="2022-06-14T00:00:00+05:30" valueDate="2022-06-14" narration="9UPI/RAKESH KUMAR KH/216513632305/UPI" reference="UPI-216512500252" /><Transaction txnId="S52219985" type="DEBIT" mode="OTHERS" amount="80.0" currentBalance="999.44" transactionTimestamp="2022-06-14T00:00:00+05:30" valueDate="2022-06-14" narration="6UPI/RAJORIYA DK RES/216534278929/Oid202206141402" reference="UPI-216512585462" /><Transaction txnId="S52543272" type="DEBIT" mode="OTHERS" amount="90.0" currentBalance="999.44" transactionTimestamp="2022-06-14T00:00:00+05:30" valueDate="2022-06-14" narration="7UPI/DOLARAJ PANDEY/216535664081/Oid202206141422" reference="UPI-216512923895" /></Transactions></Account>"###;

        let (encoded_public_key, encoded_nonce, secretkey_p0, secretkey_p1, secretkey_p2) =
            test_run_dkg();

        println!("our nonce: {}", encoded_nonce);
        println!("remote nonce: {}", remote_nonce);

        println!("public key: {}", encoded_public_key);

        // let encoded_data = BASE64_STANDARD.encode(input);
        let enc_request = EncryptionRequest {
            base64_remote_nonce: encoded_nonce.clone(),
            base64_your_nonce: remote_nonce.clone(),
            data: input.to_string(),
            our_private_key: remote_secret_key,
            remote_key_material: RemoteKeyMaterial {
                dhpublic_key: DHPublicKey {
                    expiry: timestamp,
                    parameters: Some("".to_string()),
                    key_value: encoded_public_key,
                },
                crypto_alg: "ECDH".to_string(),
                curve: "Curve25519".to_string(),
                params: "".to_string(),
            },
        };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("accept", "application/json".parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());
        let client = Client::new();
        let request = client
            .request(
                reqwest::Method::POST,
                "https://rahasya.openbanking.silencelaboratories.com/ecc/v1/encrypt",
            )
            .headers(headers)
            .json(&enc_request);
        let response = request.send().await.unwrap();
        let body = response.text().await.unwrap();
        let response_json: EncryptionResponse = serde_json::from_str(&body).unwrap(); // Parse the response
        let b64_ciphertext = response_json.base64_data.unwrap();
        //println!("{:?}", b64_ciphertext);

        let plaintext = GetDataPltextInput {
            remote_nonce,
            our_nonce: encoded_nonce,
            remote_public_key,
            ciphertext: b64_ciphertext,
        };

        let params = [
            (plaintext.clone(), secretkey_p0),
            (plaintext.clone(), secretkey_p1),
            (plaintext.clone(), secretkey_p2),
        ];

        let results = sim_get_data(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let transac_p1 = results[0].clone();
        let transac_p2 = results[1].clone();
        let transac_p3 = results[2].clone();

        let expected_txn_id = [
            "S25836278~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "S18628747~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "S18624783~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "S30323399~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "S25864256~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "S42506559~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "S34780351~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "S52138551~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "S52219985~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "S52543272~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
        ];
        let expected_type_credit = [
            false, true, true, false, false, false, false, true, false, false,
        ];
        let expected_txn_mode = [
            "OTH".to_string(),
            "OTH".to_string(),
            "OTH".to_string(),
            "OTH".to_string(),
            "OTH".to_string(),
            "OTH".to_string(),
            "OTH".to_string(),
            "OTH".to_string(),
            "OTH".to_string(),
            "OTH".to_string(),
        ];
        let expected_txn_amt = [
            Decimal::from_i128_with_scale(40000, 2),
            Decimal::from_i128_with_scale(10000, 2),
            Decimal::from_i128_with_scale(178100, 2),
            Decimal::from_i128_with_scale(14875, 2),
            Decimal::from_i128_with_scale(15000, 2),
            Decimal::from_i128_with_scale(1900, 2),
            Decimal::from_i128_with_scale(4400, 2),
            Decimal::from_i128_with_scale(14000, 2),
            Decimal::from_i128_with_scale(8000, 2),
            Decimal::from_i128_with_scale(9000, 2),
        ];
        let expected_curr_bal = [
            Decimal::from_i128_with_scale(119344, 2),
            Decimal::from_i128_with_scale(119344, 2),
            Decimal::from_i128_with_scale(119344, 2),
            Decimal::from_i128_with_scale(119344, 2),
            Decimal::from_i128_with_scale(119344, 2),
            Decimal::from_i128_with_scale(113044, 2),
            Decimal::from_i128_with_scale(113044, 2),
            Decimal::from_i128_with_scale(99944, 2),
            Decimal::from_i128_with_scale(99944, 2),
            Decimal::from_i128_with_scale(99944, 2),
        ];
        let expected_narration = [
            "PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:56~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI/YOGESH MALVIYA/216305036794/NA~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI/YOGESH MALVIYA/216305030230/NA~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI/RazorpayZomato/216386232803/ZomatoOnlineOrd~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:58~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI/Dheerendra Jain/216464548973/Oid202206131918~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI/Dheerendra Jain/216418410134/Oid202206131028~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI/RAKESH KUMAR KH/216513632305/UPI~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI/RAJORIYA DK RES/216534278929/Oid202206141402~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI/DOLARAJ PANDEY/216535664081/Oid202206141422~~~~~~~~~~~~~~~~~~~~~~".to_string(),
        ];
        let expected_reference = [
            "216311406416~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI-216377280207~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI-216377277537~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI-216389748326~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "216311406641~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI-216402403500~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI-216494338490~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI-216512500252~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI-216512585462~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
            "UPI-216512923895~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string(),
        ];
        let expected_category = [1, 9, 9, 2, 3, 4, 5, 9, 6, 7];

        for i in 0..transac_p1.len() {
            let txn_id = reconstruct_byte_share_to_string(
                transac_p1[i].txn_id.clone(),
                transac_p2[i].txn_id.clone(),
                transac_p3[i].txn_id.clone(),
            );
            assert_eq!(expected_txn_id[i], txn_id);

            let type_credit = reconstruct_binary_share(
                transac_p1[i].type_credit,
                transac_p2[i].type_credit,
                transac_p3[i].type_credit,
            );
            assert_eq!(expected_type_credit[i], type_credit);

            let txn_mode = reconstruct_byte_share_to_string(
                transac_p1[i].txn_mode.to_vec(),
                transac_p2[i].txn_mode.to_vec(),
                transac_p3[i].txn_mode.to_vec(),
            );
            assert_eq!(expected_txn_mode[i], txn_mode);

            let txn_amt = reconstruct_decimal(
                transac_p1[i].txn_amt,
                transac_p2[i].txn_amt,
                transac_p3[i].txn_amt,
            );
            assert_eq!(expected_txn_amt[i], txn_amt);

            let curr_bal = reconstruct_decimal(
                transac_p1[i].curr_bal,
                transac_p2[i].curr_bal,
                transac_p3[i].curr_bal,
            );
            assert_eq!(expected_curr_bal[i], curr_bal);

            let narration = reconstruct_byte_share_to_string(
                transac_p1[i].narration.clone(),
                transac_p2[i].narration.clone(),
                transac_p3[i].narration.clone(),
            );
            assert_eq!(expected_narration[i], narration);

            let reference = reconstruct_byte_share_to_string(
                transac_p1[i].reference.clone(),
                transac_p2[i].reference.clone(),
                transac_p3[i].reference.clone(),
            );
            assert_eq!(expected_reference[i], reference);

            assert_eq!(expected_category[i], transac_p1[i].category);
            assert_eq!(expected_category[i], transac_p2[i].category);
            assert_eq!(expected_category[i], transac_p3[i].category);
        }

        // let mut file = fs::File::create("./data.txt").unwrap();
        // file.write(serde_json::to_string(&transac_p1).unwrap().as_bytes()).unwrap();
        // file.write("\n".as_bytes()).unwrap();
        // file.write(serde_json::to_string(&transac_p2).unwrap().as_bytes()).unwrap();
        // file.write("\n".as_bytes()).unwrap();
        // file.write(serde_json::to_string(&transac_p3).unwrap().as_bytes()).unwrap();
        // assert!(false);
    }
}
