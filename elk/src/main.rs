//! # `elk` - Executable and Linker Kit

use anyhow::Context;
use std::{env, fs};

fn main() -> anyhow::Result<()> {
    let input_path = env::args().nth(1).context("usage: elk FILE")?;
    let input = fs::read(&input_path)?;

    let file = delf::File::parse(&input[..])?;

    println!("{:#?}", file);

    Ok(())
}
