use crate::audit_commands;
use crate::cli::{Cli, Commands, RunArgs, SetupArgs};
use crate::command_runtime::{run_sandbox, run_shell, run_wrap};
use crate::completions::run_completions;
use crate::deprecated_policy;
use crate::learn_runtime::run_learn;
use crate::open_url_runtime::run_open_url_helper;
use crate::output;
use crate::package_cmd;
use crate::profile_cmd;
use crate::proxy_command;
use crate::registry_client::PullReason;
use crate::rollback_commands;
use crate::session_commands;
use crate::setup;
use crate::startup_runtime::{
    allows_pre_exec_update_check, run_detached_launch, show_update_notification,
};
use crate::trust_cmd;
use crate::update_check;
use crate::why_runtime::run_why;
use crate::{DETACHED_LAUNCH_ENV, Result};

pub(crate) fn run(cli: Cli) -> Result<()> {
    let mut update_handle = start_update_check_handle(&cli);
    dispatch_command(cli.command, cli.silent, &mut update_handle)
}

fn start_update_check_handle(cli: &Cli) -> Option<update_check::UpdateCheckHandle> {
    if !cli.silent && allows_pre_exec_update_check(&cli.command) {
        update_check::start_background_check()
    } else {
        None
    }
}

fn dispatch_command(
    command: Commands,
    silent: bool,
    update_handle: &mut Option<update_check::UpdateCheckHandle>,
) -> Result<()> {
    match command {
        Commands::Learn(args) => run_learn(*args, silent),
        Commands::Run(args) => {
            run_command_with_update(update_handle, silent, || run_or_detach(*args, silent))
        }
        Commands::Shell(args) => {
            run_command_with_banner_and_update(update_handle, silent, || run_shell(*args, silent))
        }
        Commands::Wrap(args) => {
            run_command_with_banner_and_update(update_handle, silent, || run_wrap(*args, silent))
        }
        Commands::Why(args) => run_command_with_update(update_handle, silent, || run_why(*args)),
        Commands::Proxy(args) => run_command_with_update(update_handle, silent, || {
            proxy_command::run_proxy(*args, silent)
        }),
        Commands::Setup(args) => {
            run_command_with_banner_and_update(update_handle, silent, || run_setup(args))
        }
        Commands::Rollback(args) => run_command_with_update(update_handle, silent, || {
            rollback_commands::run_rollback(args)
        }),
        Commands::Trust(args) => {
            run_command_with_update(update_handle, silent, || trust_cmd::run_trust(args))
        }
        Commands::Audit(args) => {
            run_command_with_update(update_handle, silent, || audit_commands::run_audit(args))
        }
        Commands::Ps(args) => {
            run_command_with_update(update_handle, silent, || session_commands::run_ps(&args))
        }
        Commands::Stop(args) => {
            run_command_with_update(update_handle, silent, || session_commands::run_stop(&args))
        }
        Commands::Detach(args) => run_command_with_update(update_handle, silent, || {
            session_commands::run_detach(&args)
        }),
        Commands::Attach(args) => run_command_with_update(update_handle, silent, || {
            session_commands::run_attach(&args)
        }),
        Commands::Logs(args) => {
            run_command_with_update(update_handle, silent, || session_commands::run_logs(&args))
        }
        Commands::Inspect(args) => run_command_with_update(update_handle, silent, || {
            session_commands::run_inspect(&args)
        }),
        Commands::Prune(args) => {
            run_command_with_update(update_handle, silent, || session_commands::run_prune(&args))
        }
        Commands::Session(args) => {
            run_command_with_update(update_handle, silent, || match args.command {
                crate::cli::SessionCommands::Cleanup(args) => session_commands::run_prune(&args),
            })
        }
        Commands::Policy(args) => {
            run_command_with_update(update_handle, silent, || deprecated_policy::dispatch(args))
        }
        Commands::Profile(args) => {
            run_command_with_update(update_handle, silent, || profile_cmd::run_profile(args))
        }
        Commands::Pull(args) => run_command_with_update(update_handle, silent, || {
            package_cmd::run_pull(args, PullReason::Explicit)
        }),
        Commands::Remove(args) => {
            run_command_with_update(update_handle, silent, || package_cmd::run_remove(args))
        }
        Commands::Update(args) => {
            run_command_with_update(update_handle, silent, || package_cmd::run_update(args))
        }
        Commands::Search(args) => {
            run_command_with_update(update_handle, silent, || package_cmd::run_search(args))
        }
        Commands::List(args) => {
            run_command_with_update(update_handle, silent, || package_cmd::run_list(args))
        }
        Commands::Pin(args) => {
            run_command_with_update(update_handle, silent, || package_cmd::run_pin(args))
        }
        Commands::Unpin(args) => {
            run_command_with_update(update_handle, silent, || package_cmd::run_unpin(args))
        }
        Commands::Outdated(args) => {
            run_command_with_update(update_handle, silent, || package_cmd::run_outdated(args))
        }
        Commands::Pack(args) => {
            run_command_with_update(update_handle, silent, || package_cmd::run_pack(args))
        }
        Commands::OpenUrlHelper(args) => run_open_url_helper(args),
        Commands::PackUpdateHintHelper(args) => crate::pack_update_hint::run_refresh_helper(args),
        Commands::Completions(args) => run_completions(args),
    }
}

fn run_command_with_update<T>(
    update_handle: &mut Option<update_check::UpdateCheckHandle>,
    silent: bool,
    command: impl FnOnce() -> Result<T>,
) -> Result<T> {
    show_update_notification(update_handle, silent);
    command()
}

fn run_command_with_banner_and_update<T>(
    update_handle: &mut Option<update_check::UpdateCheckHandle>,
    silent: bool,
    command: impl FnOnce() -> Result<T>,
) -> Result<T> {
    output::print_banner(silent);
    run_command_with_update(update_handle, silent, command)
}

fn run_or_detach(args: RunArgs, silent: bool) -> Result<()> {
    if args.detached && std::env::var_os(DETACHED_LAUNCH_ENV).is_none() {
        run_detached_launch(args, silent)
    } else {
        output::print_banner(silent);
        run_sandbox(args, silent)
    }
}

fn run_setup(args: SetupArgs) -> Result<()> {
    let runner = setup::SetupRunner::new(&args);
    runner.run()
}
