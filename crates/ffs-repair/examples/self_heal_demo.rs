use ffs_repair::demo::{SelfHealDemoConfig, run_self_heal_demo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
