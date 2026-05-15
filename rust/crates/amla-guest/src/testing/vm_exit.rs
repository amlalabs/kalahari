//! VM exit helper for integration tests.

/// Run vm-exit subcommand. Returns exit code (but usually doesn't return).
pub fn run(args: &[String]) -> i32 {
    if args.len() > 1 {
        super::kmsg("Usage: amla-guest vm-exit [exit_code]");
        super::kmsg("Error: unexpected extra arguments");
        super::vm_exit(1);
    }
    let code = args.first().map_or(0u8, |arg| match arg.parse::<u8>() {
        Ok(c) => {
            if c > 127 {
                super::kmsg(&format!(
                    "Warning: exit code {c} exceeds effective range 0-127 \
                     (VMM-side formula overflows for values >= 128)"
                ));
            }
            c
        }
        Err(e) => {
            super::kmsg(&format!("Invalid exit code '{arg}': {e}"));
            super::vm_exit(1);
        }
    });
    super::vm_exit(code);
}
