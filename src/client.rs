use chrono::{DateTime, Utc};
use failure::Fail;
use hmac::{Hmac, Mac, NewMac};
use reqwest::{Client, Method, header::{self, CONTENT_TYPE}};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;


const FTX_OTC_URL: &str = "https://otc.ftx.com/api";

fn build_client(api_key: &str, signature: String, date: DateTime<Utc>) -> Result<Client, Error> {
    let mut headers = header::HeaderMap::new();
    let api_key = header::HeaderValue::from_str(&api_key).expect("Invalid header value");
    let signature = header::HeaderValue::from_str(&signature).expect("Invalid header value");
    let ts = date.timestamp_millis();
    let timestamp =
        header::HeaderValue::from_str(&format!("{}", ts)).expect("Invalid header value");
    headers.insert("FTX-APIKEY", api_key);
    headers.insert("FTX-TIMESTAMP", timestamp);
    headers.insert("FTX-SIGNATURE", signature);
    headers.insert(CONTENT_TYPE, header::HeaderValue::from_static("application/json"));

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(Into::into)
}

type HmacSha256 = Hmac<Sha256>;
fn sign(
    secret: &str,
    method: Method,
    path: String,
    date: DateTime<Utc>,
    body: Option<Value>,
) -> String {
    let mut mac =
        HmacSha256::new_varkey(secret.as_bytes()).expect("could not load hmac");
    let mut param = format!(
        "{}{}{}",
        date.timestamp_millis(),
        method.to_string(),
        path
    );

    if let Some(body) = body {
        param = format!("{}{}", param, body.to_string());
    }

    mac.update(param.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    hex::encode(code_bytes)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Side {
    Buy,
    Sell,
    TwoWay
}
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RequestQuote {
    base_currency: String,
    quote_currency: String,
    // either this or quote_currency_size needs to be specified
    base_currency_size: Option<f64>,
    // either this or base_currency_size needs to be specified
    quote_currency_size: Option<f64>,
    wait_for_price: bool,
    side: Side,
    api_only: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RequestedQuote {
    id: i64,
    side: Side,
    base_currency: String,
    quote_currency: String,
    base_currency_size: Option<f64>,
    quote_currency_size: Option<f64>,
    price: f64,
    requested_at: DateTime<Utc>,
    quoted_at: DateTime<Utc>,
    expiry: DateTime<Utc>,
}

#[derive(Deserialize, Debug)]
pub struct FtxResponse<Data> {
    success: bool,
    result: Option<Data>,
    error: Option<String>,
    error_code: Option<i32>,
}

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "SerdeJsonError {}", _0)]
    SerdeJsonError(serde_json::Error),
    #[fail(display = "DecodingError {:?} - {}", _0, _1)]
    DecodingError(Value, serde_json::Error),
    #[fail(display = "Networking: {:?}", _0)]
    Networking(reqwest::Error),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::SerdeJsonError(e)
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Error {
        Error::Networking(e)
    }
}


pub async fn request_quote(
    api_key: &str,
    api_secret: &str,
    base_currency: String,
    quote_currency: String,
    side: Side,
    base_currency_size: Option<f64>,
    quote_currency_size: Option<f64>,
) -> Result<FtxResponse<RequestedQuote>, Error> {
    assert!(side != Side::TwoWay);

    let body = RequestQuote {
        base_currency: base_currency.clone(),
        quote_currency: quote_currency.clone(),
        side,
        base_currency_size,
        quote_currency_size,
        wait_for_price: true,
        api_only: true,
    };
    let path = format!("/otc/quotes");
    let now = Utc::now();
    let value = serde_json::to_value(body.clone())?;
    let signature = sign(api_secret, Method::POST, path.clone(), now, Some(value.clone()));

    let client = build_client(api_key, signature, now)?;

    let resp = client
        .post(&format!("{}{}", FTX_OTC_URL, path))
        .json(&value)
        .send()
        .await?
        .json::<Value>()
        .await?;

    serde_json::from_value::<FtxResponse<RequestedQuote>>(resp.clone())
        .map_err(|err| Error::DecodingError(resp, err))
}


pub async fn request_two_way_quotes(
    api_key: &str,
    api_secret: &str,
    base_currency: String,
    quote_currency: String,
    base_currency_size: Option<f64>,
    quote_currency_size: Option<f64>,
) -> Result<FtxResponse<Vec<RequestedQuote>>, Error> {
    let body = RequestQuote {
        base_currency: base_currency.clone(),
        quote_currency: quote_currency.clone(),
        side: Side::TwoWay,
        base_currency_size,
        quote_currency_size,
        wait_for_price: true,
        api_only: true,
    };
    let path = format!("/otc/quotes");
    let now = Utc::now();
    let value = serde_json::to_value(body.clone())?;
    let signature = sign(api_secret, Method::POST, path.clone(), now, Some(value.clone()));

    let client = build_client(api_key, signature, now)?;

    let resp = client
        .post(&format!("{}{}", FTX_OTC_URL, path))
        .json(&value)
        .send()
        .await?
        .json::<Value>()
        .await?;

    serde_json::from_value::<FtxResponse<Vec<RequestedQuote>>>(resp.clone())
        .map_err(|err| Error::DecodingError(resp, err))
}
