// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn server_metrics_encode_build_logging_and_process_metrics() -> Result<(), fmt::Error> {
    let (writer, _guard) = tracing_appender::non_blocking(std::io::sink());
    let metrics = ServerMetrics::new(
        &BuildInfo {
            version: "1.2.3",
            branch: "main",
            commit: "abc1234",
        },
        writer.error_counter(),
    );
    let mut body = String::new();
    prometheus_client::encoding::text::encode(&mut body, &metrics.into_registry())?;
    assert!(body.lines().any(|line| line
        == "lonewolf_build_info{version=\"1.2.3\",branch=\"main\",commit=\"abc1234\"} 1"));
    assert!(
        body.lines()
            .any(|line| line == "lonewolf_log_dropped_lines_total 0")
    );
    assert!(
        body.lines()
            .any(|line| line.starts_with("process_cpu_seconds_total "))
    );
    Ok(())
}
