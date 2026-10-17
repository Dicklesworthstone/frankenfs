use std::env;

use ffs_repair::demo::{SelfHealDemoConfig, run_self_heal_demo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args.as_slice(), [cmd] if cmd == "self-healing") {
        // no-op
    } else if matches!(args.as_slice(), [cmd] if cmd == "--help" || cmd == "-h" || cmd == "help") {
        print_usage();
        return Ok(());
    } else {
        print_usage();
        return Err("unknown command (expected: self-healing)".into());
    }

    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .map_err(|err| err.to_string())?;
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let result = run_self_heal_demo(&cx, &SelfHealDemoConfig::default())?;
    for line in result.output_lines {
        println!("{line}");
    }
    Ok(())
}

fn print_usage() {
    println!("ffs-demo — self-healing demo");
    println!();
    println!("USAGE:");
    println!("  ffs-demo self-healing");
}
