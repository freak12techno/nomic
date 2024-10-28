use orga::client::Client as OrgaClient;
use reqwest::get;
use serde::{Deserialize, Serialize};

use super::{Bootstrap, Bytes32, LightClient, Update};
use crate::error::Result;

/// Based on the current Nomic state machine state, get the updates needed to
/// bring the light client up to date with the Ethereum chain.
///
/// This may include any number of updates that advance the light client to the
/// next light client period (256 epochs) and a finality update that advances
/// the light client to the most recently finalized slot within the current
/// period.
///
/// If the light client is already up to date, this function will return an
/// empty vector.
pub async fn get_updates<C: OrgaClient<LightClient>>(
    app_client: &C,
    eth_client: &RpcClient,
) -> Result<Vec<Update>> {
    let lc = app_client.query(Ok).await?;

    let finality_update = eth_client.get_finality_update().await?.data;

    let app_epoch = lc.slot() / 32;
    let eth_epoch = finality_update.finalized_header.beacon.slot / 32;

    let app_period = app_epoch / 256;
    let eth_period = eth_epoch / 256;

    let mut updates = vec![];

    let updates_needed = eth_period - app_period;
    if updates_needed > 0 {
        updates = eth_client
            .get_updates(app_period, updates_needed)
            .await?
            .into_iter()
            .map(|u| u.data)
            .collect();
    }

    if eth_epoch > app_epoch {
        updates.push(finality_update);
    }

    Ok(updates)
}

/// A client for the Ethereum Beacon API.
pub struct RpcClient {
    rpc_addr: String,
}

impl RpcClient {
    /// Create a new client to the Beacon API server with the given address.
    pub fn new(rpc_addr: String) -> Self {
        Self { rpc_addr }
    }

    /// Get the updates, if any, to advance the light client from the given
    /// start period to the current period, up to the given count.
    pub async fn get_updates(
        &self,
        start_period: u64,
        count: u64,
    ) -> Result<Vec<Response<Update>>> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={}&count={}",
            self.rpc_addr, start_period, count,
        );
        let response = get(&url)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        let res = response
            .json()
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        Ok(res)
    }

    /// Get the most recent finality update.
    pub async fn get_finality_update(&self) -> Result<Response<Update>> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/finality_update",
            self.rpc_addr,
        );
        let response = get(&url)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        let res = response
            .json()
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        Ok(res)
    }

    /// Get the block root for the given slot.
    pub async fn block_root(&self, slot: u64) -> Result<Response<Root>> {
        let url = format!("{}/eth/v1/beacon/blocks/{}/root", self.rpc_addr, slot,);
        let response = get(&url)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        let res = response
            .json()
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        Ok(res)
    }

    /// Get the bootstrap data for the given block root.
    pub async fn bootstrap(&self, block_root: Bytes32) -> Result<Response<Bootstrap>> {
        let url = format!(
            "{}/eth/v1/beacon/light_client/bootstrap/{}",
            self.rpc_addr, block_root,
        );
        let response = get(&url)
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        let res = response
            .json()
            .await
            .map_err(|e| orga::Error::App(e.to_string()))?;
        Ok(res)
    }
}

/// A response from the Beacon API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response<T> {
    pub version: Option<String>,
    pub data: T,
}

/// A response containing a block root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Root {
    pub root: Bytes32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_updates() {
        let client = RpcClient::new("https://www.lightclientdata.org".to_string());
        let updates = client.get_updates(1229, 1).await.unwrap();
        let update = client.get_finality_update().await.unwrap();
        let bootstrap = client
            .bootstrap(
                "0xb2536a96e35df54caf8d37e958d2899a6c6b8616342a9e38c913c62e5c85aa93"
                    .parse()
                    .unwrap(),
            )
            .await
            .unwrap();
    }
}
