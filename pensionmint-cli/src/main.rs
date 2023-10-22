use pensionmint_cli::PensionmintCli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    PensionmintCli::new()?
        .with_default_modules()
        .with_module(pensionmint_client::PensionClientGen)
        .run()
        .await;
    Ok(())
}