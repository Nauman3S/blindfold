//! Short binary alias for the Blindfold command-line interface.

#![forbid(unsafe_code)]

use std::process::ExitCode;

mod commands;
mod config;
mod doctor;

#[tokio::main]
async fn main() -> ExitCode {
    commands::run().await
}
