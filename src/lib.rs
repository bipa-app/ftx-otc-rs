use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{
    header::{self, InvalidHeaderValue, CONTENT_TYPE},
    Client, Method,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

const FTX_OTC_URL: &str = "https://otc.ftx.com/api";

fn build_client(api_key: &str, signature: String, date: DateTime<Utc>) -> Result<Client, Error> {
    let mut headers = header::HeaderMap::new();
    let api_key = header::HeaderValue::from_str(&api_key).map_err(Error::HeaderError)?;
    let signature = header::HeaderValue::from_str(&signature).map_err(Error::HeaderError)?;
    let ts = date.timestamp_millis();
    let timestamp =
        header::HeaderValue::from_str(&format!("{}", ts)).map_err(Error::HeaderError)?;

    headers.insert("FTX-APIKEY", api_key);
    headers.insert("FTX-TIMESTAMP", timestamp);
    headers.insert("FTX-SIGNATURE", signature);
    headers.insert(
        CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );

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
) -> Result<String, Error> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(Error::InvalidHmacKey)?;
    let mut param = format!("{}{}{}", date.timestamp_millis(), method.to_string(), path);

    if let Some(body) = body {
        param = format!("{}{}", param, body.to_string());
    }

    mac.update(param.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    Ok(hex::encode(code_bytes))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Side {
    Buy,
    Sell,
    TwoWay,
}
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RequestQuote {
    base_currency: FtxCurrency,
    quote_currency: FtxCurrency,
    // either this or quote_currency_size needs to be specified
    base_currency_size: Option<f64>,
    // either this or base_currency_size needs to be specified
    quote_currency_size: Option<f64>,
    wait_for_price: bool,
    side: Side,
    api_only: bool,
}

#[derive(Deserialize, Debug)]
pub struct FtxResponse<Data> {
    pub success: bool,
    pub result: Option<Data>,
    pub error: Option<String>,
    pub error_code: Option<i32>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("SerdeJsonError {0}")]
    SerdeJsonError(serde_json::Error),
    #[error("DecodingError {0:?}")]
    DecodingError(serde_json::Error),
    #[error("Networking: {0:?}")]
    Networking(reqwest::Error),
    #[error("FtxResponseError: {0} ({1})")]
    FtxResponseError(String, i32),
    #[error("Invalid Header Error: {0:?}")]
    HeaderError(InvalidHeaderValue),
    #[error("Error decoding Hmac: {0:?}")]
    InvalidHmacKey(hmac::digest::InvalidLength),
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

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Quote {
    pub id: i64,
    pub side: Side,
    pub base_currency: FtxCurrency,
    pub quote_currency: FtxCurrency,
    pub base_currency_size: Option<f64>,
    pub quote_currency_size: Option<f64>,
    pub proceeds: Option<f64>,
    pub proceeds_currency: FtxCurrency,
    pub cost: Option<f64>,
    pub cost_currency: FtxCurrency,
    pub order_id: Option<i64>,
    pub price: Option<f64>,
    pub requested_at: DateTime<Utc>,
    pub quoted_at: DateTime<Utc>,
    pub expiry: Option<DateTime<Utc>>,
    pub user_fully_settled_at: Option<DateTime<Utc>>,
}

pub async fn accept_quote_with_custom_size(
    api_key: &str,
    api_secret: &str,
    quote_id: i64,
    custom_size: f64,
) -> Result<Quote, Error> {
    let path = format!("/otc/quotes/{}/accept", quote_id);
    let now = Utc::now();
    let body = serde_json::json!({ "customSize": custom_size });
    let signature = sign(
        api_secret,
        Method::POST,
        path.clone(),
        now,
        Some(body.clone()),
    )?;

    let client = build_client(api_key, signature, now)?;

    let resp = client
        .post(&format!("{}{}", FTX_OTC_URL, path))
        .json(&body)
        .send()
        .await?
        .json::<Value>()
        .await?;

    let response = serde_json::from_value::<FtxResponse<Quote>>(resp.clone())
        .map_err(|err| Error::DecodingError(err))?;

    if !response.success || response.result.is_none() {
        return Err(Error::FtxResponseError(
            response.error.unwrap_or("FTX Unknown error".to_string()),
            response.error_code.unwrap_or(-1),
        ));
    }

    Ok(response.result.unwrap())
}

pub async fn accept_quote(api_key: &str, api_secret: &str, quote_id: i64) -> Result<Quote, Error> {
    let path = format!("/otc/quotes/{}/accept", quote_id);
    let now = Utc::now();
    let signature = sign(api_secret, Method::POST, path.clone(), now, None)?;

    let client = build_client(api_key, signature, now)?;

    let resp = client
        .post(&format!("{}{}", FTX_OTC_URL, path))
        .send()
        .await?
        .json::<Value>()
        .await?;

    let response = serde_json::from_value::<FtxResponse<Quote>>(resp.clone())
        .map_err(|err| Error::DecodingError(err))?;

    if !response.success || response.result.is_none() {
        return Err(Error::FtxResponseError(
            response.error.unwrap_or("FTX Unknown error".to_string()),
            response.error_code.unwrap_or(-1),
        ));
    }

    Ok(response.result.unwrap())
}

pub async fn request_quote(
    api_key: &str,
    api_secret: &str,
    base_currency: FtxCurrency,
    quote_currency: FtxCurrency,
    side: Side,
    base_currency_size: Option<f64>,
    quote_currency_size: Option<f64>,
) -> Result<Quote, Error> {
    debug_assert!(side != Side::TwoWay);
    debug_assert!(base_currency_size != None || quote_currency_size != None);

    let body = RequestQuote {
        base_currency,
        quote_currency,
        side,
        base_currency_size,
        quote_currency_size,
        wait_for_price: true,
        api_only: true,
    };
    let path = format!("/otc/quotes");
    let now = Utc::now();
    let value = serde_json::to_value(body.clone())?;
    let signature = sign(
        api_secret,
        Method::POST,
        path.clone(),
        now,
        Some(value.clone()),
    )?;

    let client = build_client(api_key, signature, now)?;

    let resp = client
        .post(&format!("{}{}", FTX_OTC_URL, path))
        .json(&value)
        .send()
        .await?
        .json::<Value>()
        .await?;

    let response = serde_json::from_value::<FtxResponse<Quote>>(resp.clone())
        .map_err(|err| Error::DecodingError(err))?;

    if !response.success || response.result.is_none() {
        return Err(Error::FtxResponseError(
            response.error.unwrap_or("FTX Unknown error".to_string()),
            response.error_code.unwrap_or(-1),
        ));
    }

    Ok(response.result.unwrap())
}

pub async fn request_two_way_quotes(
    api_key: &str,
    api_secret: &str,
    base_currency: FtxCurrency,
    quote_currency: FtxCurrency,
    base_currency_size: Option<f64>,
    quote_currency_size: Option<f64>,
) -> Result<Vec<Quote>, Error> {
    debug_assert!(base_currency_size != None || quote_currency_size != None);

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
    let signature = sign(
        api_secret,
        Method::POST,
        path.clone(),
        now,
        Some(value.clone()),
    )?;

    let client = build_client(api_key, signature, now)?;

    let resp = client
        .post(&format!("{}{}", FTX_OTC_URL, path))
        .json(&value)
        .send()
        .await?
        .json::<Value>()
        .await?;

    let response = serde_json::from_value::<FtxResponse<Vec<Quote>>>(resp.clone())
        .map_err(|err| Error::DecodingError(err))?;

    if !response.success || response.result.is_none() {
        return Err(Error::FtxResponseError(
            response.error.unwrap_or("FTX Unknown error".to_string()),
            response.error_code.unwrap_or(-1),
        ));
    }

    Ok(response.result.unwrap())
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum FtxCurrency {
    Btc,
    Brl,
    Brz,
    Paxg,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FtxAssetBalance {
    pub currency: FtxCurrency,
    pub total: f64,
    pub locked: f64,
    pub unsettled_proceeds: f64,
    pub unsettled_costs: f64,
    pub overall: f64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct FtxBalances {
    pub btc: FtxAssetBalance,
    pub brz: FtxAssetBalance,
    pub paxg: FtxAssetBalance,
}

pub async fn get_ftx_balances(api_key: &str, api_secret: &str) -> Result<FtxBalances, Error> {
    let path = format!("/balances");
    let now = Utc::now();
    let signature = sign(api_secret, Method::GET, path.clone(), now, None)?;

    let client = build_client(api_key, signature, now)?;

    let resp = client
        .get(&format!("{}{}", FTX_OTC_URL, path))
        .send()
        .await?
        .json::<Value>()
        .await?;

    let response = serde_json::from_value::<FtxResponse<FtxBalances>>(resp.clone())
        .map_err(|err| Error::DecodingError(err))?;

    if !response.success || response.result.is_none() {
        return Err(Error::FtxResponseError(
            response.error.unwrap_or("FTX Unknown error".to_string()),
            response.error_code.unwrap_or(-1),
        ));
    }

    Ok(response.result.unwrap())
}
