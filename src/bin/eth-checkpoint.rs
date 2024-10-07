use clap::Parser;
use nomic::error::Result;
use nomic::ethereum::consensus::relayer::RpcClient;

#[derive(Parser, Debug)]
pub struct Opts {
    #[clap(long)]
    rpc_url: String,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let opts = Opts::parse();
    let client = RpcClient::new(opts.rpc_url.clone());

    // get block root
    let res: serde_json::Value = reqwest::get(format!("{}/eth/v1/beacon/headers", opts.rpc_url))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    dbg!(&res);
    // ?: is this the correct hash?
    // let block_root = &res["data"][0]["root"];
    let block_root = &res["data"][0]["header"]["message"]["parent_root"];
    println!("{}", block_root);

    let bootstrap = client
        .bootstrap(block_root.as_str().unwrap().parse().unwrap())
        .await;

    dbg!(&bootstrap);

    Ok(())
}
