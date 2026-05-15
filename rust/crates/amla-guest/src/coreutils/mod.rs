//! Minimal multi-call coreutils for guest VMs.
//!
//! Dispatches by subcommand name. Each applet is a standalone command.

pub mod cmd;

/// Run a coreutils applet by name. Returns exit code.
pub fn run(name: &str, args: &[String]) -> i32 {
    use lexopt::prelude::*;

    let parser = lexopt::Parser::from_args(args.iter().map(String::as_str));

    if name == "coreutils" {
        // First positional arg is the applet name.
        let mut parser = parser;
        if let Ok(Some(Value(val))) = parser.next() {
            let Ok(applet) = val.into_string() else {
                eprintln!("coreutils: invalid applet name");
                return 1;
            };
            let remaining_parser = parser;
            return dispatch(&applet, remaining_parser);
        }
        eprintln!("usage: amla-guest coreutils <applet> [args...]");
        #[cfg(not(feature = "test-binaries"))]
        eprintln!(
            "applets: echo cat id ls mkdir dirname true false printenv exit-with sleep grep nproc wget ping tee dd mount umount wc date stat"
        );
        #[cfg(feature = "test-binaries")]
        eprintln!(
            "applets: echo cat id ls mkdir dirname true false printenv exit-with sleep grep nproc wget ping tee eof-marker dd mount umount wc date stat"
        );
        return 1;
    }

    dispatch(name, parser)
}

fn dispatch(name: &str, parser: lexopt::Parser) -> i32 {
    match name {
        "echo" => cmd::echo(parser),
        "cat" => cmd::cat(parser),
        "id" => cmd::id(parser),
        "ls" => cmd::ls(parser),
        "mkdir" => cmd::mkdir(parser),
        "dirname" => cmd::dirname(parser),
        "true" => 0,
        "false" => 1,
        "printenv" => cmd::printenv(parser),
        "exit-with" => cmd::exit_with(parser),
        "sleep" => cmd::sleep_cmd(parser),
        "grep" => cmd::grep(parser),
        "nproc" => cmd::nproc(parser),
        "wget" => cmd::wget(parser),
        "ping" => cmd::ping(parser),
        "tee" => cmd::tee(parser),
        #[cfg(feature = "test-binaries")]
        "eof-marker" => cmd::eof_marker(parser),
        "dd" => cmd::dd(parser),
        "mount" => cmd::mount(parser),
        "umount" => cmd::umount(parser),
        "wc" => cmd::wc(parser),
        "date" => cmd::date(parser),
        "stat" => cmd::stat(parser),
        other => {
            eprintln!("{other}: applet not found");
            127
        }
    }
}
