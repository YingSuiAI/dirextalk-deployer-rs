use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Parser, PartialEq, Eq)]
#[command(
    name = "dirextalk-deployer",
    version,
    about = "Deploy a production Dirextalk service into your GCP project"
)]
pub struct Cli {
    /// Select stable human output or a machine-readable envelope.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human, global = true)]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: TopLevelCommand,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
#[value(rename_all = "lower")]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
    Jsonl,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum TopLevelCommand {
    /// Manage the built-in browser OAuth session.
    Auth(AuthArgs),
    /// Inspect accessible GCP projects without mutating them.
    Project(ProjectArgs),
    /// Plan, apply, resume, verify, or destroy a deployment.
    Deploy(DeployArgs),
    /// Install and diagnose the service-scoped local bridge.
    Connect(ConnectArgs),
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum AuthCommand {
    Login,
    Status,
    Logout,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommand,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum ProjectCommand {
    List,
    Inspect(ProjectInspectArgs),
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct ProjectInspectArgs {
    #[arg(long)]
    pub project: String,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct DeployArgs {
    #[command(subcommand)]
    pub command: DeployCommand,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum DeployCommand {
    Plan(ConfigArgs),
    Apply(ApprovedConfigArgs),
    Resume(ConfigArgs),
    Status(ConfigArgs),
    Verify(ConfigArgs),
    Destroy(DestroyArgs),
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct ConfigArgs {
    #[arg(long, value_name = "DEPLOYMENT_TOML")]
    pub config: PathBuf,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct ApprovedConfigArgs {
    #[arg(long, value_name = "DEPLOYMENT_TOML")]
    pub config: PathBuf,
    #[arg(long, value_name = "sha256:PLAN_ID")]
    pub approve: String,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct DestroyArgs {
    #[arg(long, value_name = "DEPLOYMENT_TOML")]
    pub config: PathBuf,
    #[arg(long, value_name = "sha256:DESTROY_PLAN_ID")]
    pub approve: Option<String>,
    /// Include the recorded boot disk in a distinct numeric-id-bound plan.
    #[arg(long, value_name = "NUMERIC_ID")]
    pub purge_disk: Option<u64>,
}

#[derive(Debug, Clone, Args, PartialEq, Eq)]
pub struct ConnectArgs {
    #[command(subcommand)]
    pub command: ConnectCommand,
}

#[derive(Debug, Clone, Subcommand, PartialEq, Eq)]
pub enum ConnectCommand {
    Install(ConfigArgs),
    Status(ConfigArgs),
    Doctor(ConfigArgs),
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{AuthCommand, Cli, DeployCommand, OutputFormat, TopLevelCommand};

    #[test]
    fn command_tree_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn output_is_global_and_destroy_purge_is_numeric() {
        let cli = Cli::try_parse_from([
            "dirextalk-deployer",
            "deploy",
            "destroy",
            "--config",
            "deployment.toml",
            "--purge-disk",
            "12345",
            "--approve",
            "sha256:abcd",
            "--output",
            "jsonl",
        ])
        .expect("valid command");
        assert_eq!(cli.output, OutputFormat::Jsonl);
        let TopLevelCommand::Deploy(deploy) = cli.command else {
            panic!("expected deploy command");
        };
        let DeployCommand::Destroy(destroy) = deploy.command else {
            panic!("expected destroy command");
        };
        assert_eq!(destroy.purge_disk, Some(12_345));
    }

    #[test]
    fn auth_status_parses() {
        let cli =
            Cli::try_parse_from(["dirextalk-deployer", "auth", "status"]).expect("valid command");
        let TopLevelCommand::Auth(auth) = cli.command else {
            panic!("expected auth command");
        };
        assert_eq!(auth.command, AuthCommand::Status);
    }
}
