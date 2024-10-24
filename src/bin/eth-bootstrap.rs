use clap::Parser;
use nomic::error::Result;
use nomic::ethereum::consensus::relayer::RpcClient;

pub const SYNC_PERIOD_LENGTH: u64 = 32 * 256;

#[derive(Parser, Debug)]
pub struct Opts {
    #[clap(long)]
    rpc_url: String,
}

#[tokio::main]
pub async fn main() -> Result<()> {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_env("NOMIC_LOG")
        .init();

    let opts = Opts::parse();
    let client = RpcClient::new(opts.rpc_url.clone());

    // get recent block
    let update = client.get_finality_update().await?;
    let current_slot = update.data.finalized_header.slot;
    log::info!("Current slot: {}", current_slot);

    // get root of start of sync period
    let start_slot = current_slot - (current_slot % SYNC_PERIOD_LENGTH);
    log::info!("Sync period start slot: {}", start_slot);
    let root = client.block_root(start_slot).await?.data.root;
    log::info!("Sync period start root: {}", &root);

    // get bootstrap data
    let bootstrap = client.bootstrap(root).await?.data;
    log::info!("Received bootstrap data");

    println!("{}", serde_json::to_string_pretty(&bootstrap).unwrap());

    Ok(())
}
