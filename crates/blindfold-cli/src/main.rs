//! Blindfold command-line interface.

#![forbid(unsafe_code)]

use std::process::ExitCode;

mod agent_adapter;
mod boundary;
mod commands;
mod config;
mod container_runner;
mod doctor;
mod host_credential;

#[tokio::main]
async fn main() -> ExitCode {
    commands::run().await
}
