use core::fmt::Display;
use encore::prelude::*;

extern crate alloc;
use alloc::borrow::Cow;

/// An error encountered while parsing CLI arguments.
#[derive(Clone)]
pub struct Error {
    /// The name of the program as it was invoked, something like
    /// `./target/release/minipak`.
    program_name: &'static str,
    /// The error message, which could be a static string (`&'static str`).
    message: Cow<'static, str>,
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "Error: {}", self.message)?;
        writeln!(f, "Usage: {} input -o output", self.program_name)?;
        Ok(())
    }
}

/// Command-line arguments for minipak.
#[derive(Debug)]
pub struct Args {
    /// The executable to compress
    pub input: &'static str,
    /// Where ot write the compressed executable on disk.
    pub output: &'static str,
}

/// Struct used while progressively parsing command line arguments.
#[derive(Default)]
struct ArgsRaw {
    input: Option<&'static str>,
    output: Option<&'static str>,
}

impl Args {
    /// Parse command-line arguments. Prints a help message and exits with a
    /// non-zero exit code if the arguments aren't quite right.
    pub fn parse(env: &Env) -> Self {
        match Self::parse_inner(env) {
            Err(e) => {
                println!("{}", e);
                syscall::exit(1);
            }

            Ok(args) => args,
        }
    }

    fn parse_inner(env: &Env) -> Result<Self, Error> {
        let mut args = env.args.iter().copied();

        // By convention, the first argument is the program's name.
        let program_name = args.next().unwrap();

        // All the fields of `ArgsRaw` are optional; we mutate it a bunch while
        // we're parsing the incoming CLI arguments.
        let mut raw: ArgsRaw = Default::default();

        // This helps us construct errors with less code.
        let err = |message| Error {
            program_name,
            message,
        };

        // Iterate through the arguments in a way that lets us get two or more
        // if we find a flag like `--output` for example.
        while let Some(arg) = args.next() {
            if arg.starts_with('-') {
                // We found a flag! Do we know what it is?
                Self::parse_flag(arg, &mut args, &mut raw, &err)?;
                continue;
            }

            // All positional arguments are just inputs. We only accept one input.
            if raw.input.is_some() {
                return Err(err("Multiple input files specified".into()));
            } else {
                raw.input = Some(arg)
            }
        }

        Ok(Args {
            input: raw.input.ok_or_else(|| err("Missing input".into()))?,
            output: raw.output.ok_or_else(|| err("Missing output".into()))?,
        })
    }

    /// Parse a single flag, and maybe the value after it.
    fn parse_flag<I, E>(
        flag: &'static str,
        args: &mut I,
        raw: &mut ArgsRaw,
        err: &E,
    ) -> Result<(), Error>
    where
        I: Iterator<Item = &'static str>,
        E: Fn(Cow<'static, str>) -> Error,
    {
        match flag {
            "-o" | "--output" => {
                let output = args
                    .next()
                    .ok_or_else(|| err("Missing output filename after -o / --output".into()))?;

                // Only accept one output.
                if raw.output.is_some() {
                    return Err(err("Multiple output files specified".into()));
                } else {
                    raw.output = Some(output)
                }

                Ok(())
            }

            x => Err(err(format!("Unknown flag {}", x).into())),
        }
    }
}
