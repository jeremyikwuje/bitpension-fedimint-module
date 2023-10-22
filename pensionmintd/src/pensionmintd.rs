use pensionmintd::pensionmintd::Pensionmintd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Pensionmintd::new()?
        .with_default_modules()
        .with_module(pensionmint_server::PensionGen)
        .with_extra_module_inits_params(
            3,
            pensionmint_server::KIND,
            pensionmint_server::PensionGenParams::default(),
        )
        .run()
        .await
}