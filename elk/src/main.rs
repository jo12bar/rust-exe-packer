//! # `elk` - Executable and Linker Kit

mod process;

use anyhow::Context;
use std::env;

fn main() -> anyhow::Result<()> {
    let input_path = env::args().nth(1).context("usage: elk FILE")?;

    let mut proc = process::Process::new();
    proc.load_object_and_dependencies(input_path)?;
    println!("{:#?}", proc);

    Ok(())
}
