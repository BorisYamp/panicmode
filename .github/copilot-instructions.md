/// Path: PanicMode/.github/copilot-instructions.md
# Copilot Instructions for PanicMode

## Overview
PanicMode is a Rust-based application designed for monitoring and alerting on system metrics. It consists of a main process that initializes various supervised tasks, each responsible for specific functionalities. The architecture is designed to ensure fail-fast behavior, where any task failure triggers a graceful shutdown of the application.

## Architecture
- **Main Process**: Initializes components, handles configuration, and manages task supervision.
- **Supervised Tasks**:
  - **Monitoring Task**: Collects system metrics (CPU, RAM, Network, Disk) and sends them to the Detector.
  - **Detector Task**: Analyzes metrics against predefined rules to detect anomalies and triggers alerts.
  - **Alert Task**: Dispatches alerts to various channels (Telegram, Discord, Email, etc.) based on detections from the Detector.
  - **Self-Check Task**: Monitors the health of the PanicMode application itself.
  - **HTTP API Task**: Optional healthcheck endpoint (`GET /health`). Auxiliary ctl task serves the Unix socket for `panicmode-ctl`.

## Developer Workflows
- **Building**: Use `cargo build` to compile the application.
- **Testing**: Run `cargo test` to execute unit tests. Ensure all tests pass before deployment.
- **Debugging**: Use `cargo run --bin <task_name>` to run specific tasks for debugging.

## Project Conventions
- **Error Handling**: All tasks utilize `Result` types for error management, ensuring that panics are caught and handled gracefully.
- **Communication**: Tasks communicate via channels (e.g., `metrics_tx`, `alert_tx`) with specific policies for message handling (e.g., drop policies, blocking sends).

## Integration Points
- **External Dependencies**: The application integrates with various external services for alerting (e.g., Twilio for SMS, Discord for notifications).
- **Cross-Component Communication**: Metrics are passed from the Monitoring Task to the Detector Task via channels, ensuring real-time processing of system data.

## Key Files/Directories
- **`src/config.rs`**: Configuration management for the application.
- **`src/main.rs`**: Entry point for the application, initializes the main process and tasks.
- **`src/action/`**: Contains the implementation of protective actions (firewall, process freeze, snapshot, script).

## Conclusion
This document serves as a guide for AI coding agents to understand the PanicMode architecture, workflows, and conventions. For further details, refer to the specific source files mentioned above.