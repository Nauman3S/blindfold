//! Blindfold command-line interface.

#![forbid(unsafe_code)]

use std::{env, process::ExitCode};

use clap::Command;

mod config;
mod doctor;

fn cli() -> Command {
    Command::new("blindfold")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Keep secrets out of agent-visible context")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("init").about("Create a safe default .blindfold.yaml"))
        .subcommand(Command::new("doctor").about("Check local Blindfold prerequisites"))
}

fn main() -> ExitCode {
    let matches = cli().get_matches();
    let root = match env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!(
                "error: could not determine the current directory: {}",
                error.kind()
            );
            return ExitCode::FAILURE;
        }
    };

    match matches.subcommand_name() {
        Some("init") => match config::init(&root) {
            Ok(()) => {
                println!("Created {} with safe defaults.", config::CONFIG_FILE);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        Some("doctor") => {
            let report = doctor::run(&root);
            report.print();
            if report.is_healthy() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        _ => ExitCode::FAILURE,
    }
}
