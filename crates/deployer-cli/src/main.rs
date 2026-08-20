use clap::Parser;
use deployer_cli::application::{Application, command_name};
use deployer_cli::cli::Cli;
use deployer_cli::output::{CommandEnvelope, stdout};
use deployer_cli::runtime::LiveControlPlane;
use deployer_cli::store::FilesystemStores;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let envelope = match (
        LiveControlPlane::new(),
        FilesystemStores::for_current_user(),
    ) {
        (Ok(control), Ok(stores)) => {
            Box::pin(Application::new(&control, &stores).execute(&cli)).await
        }
        (Err(error), _) | (_, Err(error)) => CommandEnvelope::failed(
            command_name(&cli),
            "RUNTIME_INITIALIZATION_FAILED",
            error.to_string(),
        ),
    };
    if stdout(&envelope, cli.output).is_err() {
        std::process::exit(1);
    }
    std::process::exit(i32::from(envelope.exit_code()));
}
