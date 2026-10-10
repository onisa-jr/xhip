use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

pub struct S3Client {
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub bucket: String,
    pub region: String,
}

impl S3Client {
    pub fn new(account_id: String, access_key_id: String, secret_access_key: String, bucket: String) -> Self {
        Self {
            account_id,
            access_key_id,
            secret_access_key,
            bucket,
            region: "auto".to_string(), // Cloudflare R2 standard region
        }
    }

    pub fn endpoint(&self) -> String {
        format!("https://{}.r2.cloudflarestorage.com", self.account_id)
    }

    pub fn host(&self) -> String {
        format!("{}.r2.cloudflarestorage.com", self.account_id)
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn get_signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_secret = format!("AWS4{}", self.secret_access_key);
        let k_date = Self::hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
        let k_region = Self::hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = Self::hmac_sha256(&k_region, b"s3");
        Self::hmac_sha256(&k_service, b"aws4_request")
    }

    /// Tests bucket connectivity by issuing a ListObjectsV2 request with max-keys=1
    pub fn validate_credentials(&self) -> Result<(), String> {
        let path = format!("/{}", self.bucket);
        let url = format!("{}{}?list-type=2&max-keys=1", self.endpoint(), path);

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let host = self.host();
        let payload_hash = Self::sha256_hex(b"");

        // Canonical request
        let canonical_uri = path;
        let canonical_query_string = "list-type=2&max-keys=1";
        let canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            host, payload_hash, amz_date
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";

        let canonical_request = format!(
            "GET\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_query_string, canonical_headers, signed_headers, payload_hash
        );

        // String to sign
        let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            Self::sha256_hex(canonical_request.as_bytes())
        );

        let signing_key = self.get_signing_key(&date_stamp);
        let signature = hex::encode(Self::hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id, credential_scope, signed_headers, signature
        );

        let response = ureq::get(&url)
            .header("host", &host)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("authorization", &auth_header)
            .call();

        match response {
            Ok(res) => {
                let status = res.status().as_u16();
                if (200..300).contains(&status) {
                    Ok(())
                } else {
                    Err(format!("Unexpected response status: {}", status))
                }
            }
            Err(e) => {
                Err(format!("R2 connection failed: {}. Please check your Account ID, Access Key, Secret Key, and Bucket name.", e))
            }
        }
    }

    /// Upload an object to the bucket
    pub fn put_object(&self, object_key: &str, data: &[u8], content_type: &str) -> Result<(), String> {
        let path = format!("/{}/{}", self.bucket, object_key);
        let url = format!("{}{}", self.endpoint(), path);

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let host = self.host();
        let payload_hash = Self::sha256_hex(data);

        // Canonical request
        // Ensure path encoding
        let canonical_uri = format!("/{}", path.trim_start_matches('/'));
        let canonical_query_string = "";
        let canonical_headers = format!(
            "content-type:{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            content_type, host, payload_hash, amz_date
        );
        let signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date";

        let canonical_request = format!(
            "PUT\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_query_string, canonical_headers, signed_headers, payload_hash
        );

        let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            Self::sha256_hex(canonical_request.as_bytes())
        );

        let signing_key = self.get_signing_key(&date_stamp);
        let signature = hex::encode(Self::hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id, credential_scope, signed_headers, signature
        );

        let res = ureq::put(&url)
            .header("host", &host)
            .header("content-type", content_type)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("authorization", &auth_header)
            .send(data)
            .map_err(|e| format!("Upload failed for {}: {}", object_key, e))?;

        let status = res.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("Upload failed with status code {}", status))
        }
    }

    /// List objects under a prefix
    pub fn list_objects(&self, prefix: Option<&str>) -> Result<Vec<String>, String> {
        let mut url = format!("{}/{}?list-type=2", self.endpoint(), self.bucket);
        let mut canonical_query = "list-type=2".to_string();

        if let Some(p) = prefix {
            let encoded_p = percent_encode_val(p);
            url.push_str(&format!("&prefix={}", encoded_p));
            // S3 canonical query parameters must be sorted by key name: "list-type" < "prefix"
            canonical_query = format!("list-type=2&prefix={}", encoded_p);
        }

        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let host = self.host();
        let payload_hash = Self::sha256_hex(b"");

        let canonical_uri = format!("/{}", self.bucket);
        let canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            host, payload_hash, amz_date
        );
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";

        let canonical_request = format!(
            "GET\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_query_string(&canonical_query), canonical_headers, signed_headers, payload_hash
        );

        let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            Self::sha256_hex(canonical_request.as_bytes())
        );

        let signing_key = self.get_signing_key(&date_stamp);
        let signature = hex::encode(Self::hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id, credential_scope, signed_headers, signature
        );

        let mut res = ureq::get(&url)
            .header("host", &host)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("authorization", &auth_header)
            .call()
            .map_err(|e| format!("List request failed: {}", e))?;

        let body = res.body_mut().read_to_string()
            .map_err(|e| format!("Failed to read XML response: {}", e))?;

        // Simple XML extraction for <Key>...</Key>
        let mut keys = Vec::new();
        let mut cur = &body[..];
        while let Some(start_tag) = cur.find("<Key>") {
            let rest = &cur[start_tag + 5..];
            if let Some(end_tag) = rest.find("</Key>") {
                let key = &rest[..end_tag];
                keys.push(key.to_string());
                cur = &rest[end_tag + 6..];
            } else {
                break;
            }
        }

        Ok(keys)
    }

    /// Generate a SigV4 Presigned GET URL
    pub fn generate_presigned_url(&self, object_key: &str, expires_seconds: u64) -> Result<String, String> {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let host = self.host();
        let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, self.region);
        let credential = format!("{}/{}", self.access_key_id, credential_scope);

        let path = format!("/{}/{}", self.bucket, object_key.trim_start_matches('/'));

        // Query parameters for presigned URL (must be sorted alphabetically by param name)
        let mut params = BTreeMap::new();
        params.insert("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string());
        params.insert("X-Amz-Credential", credential);
        params.insert("X-Amz-Date", amz_date);
        params.insert("X-Amz-Expires", expires_seconds.to_string());
        params.insert("X-Amz-SignedHeaders", "host".to_string());

        let mut query_parts = Vec::new();
        for (k, v) in &params {
            query_parts.push(format!("{}={}", percent_encode_val(k), percent_encode_val(v)));
        }
        let canonical_query_string = query_parts.join("&");

        let canonical_headers = format!("host:{}\n", host);
        let signed_headers = "host";
        let payload_hash = "UNSIGNED-PAYLOAD";

        let canonical_request = format!(
            "GET\n{}\n{}\n{}\n{}\n{}",
            path, canonical_query_string, canonical_headers, signed_headers, payload_hash
        );

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            now.format("%Y%m%dT%H%M%SZ"),
            credential_scope,
            Self::sha256_hex(canonical_request.as_bytes())
        );

        let signing_key = self.get_signing_key(&date_stamp);
        let signature = hex::encode(Self::hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let final_url = format!(
            "{}{}?{}&X-Amz-Signature={}",
            self.endpoint(),
            path,
            canonical_query_string,
            signature
        );

        Ok(final_url)
    }
}

fn canonical_query_string(q: &str) -> String {
    let mut pairs: Vec<&str> = q.split('&').collect();
    pairs.sort();
    pairs.join("&")
}

pub fn percent_encode_val(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", b));
            }
        }
    }
    encoded
}
