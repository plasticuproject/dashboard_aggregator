[![Rust 1.80](https://img.shields.io/badge/rust-1.80+-red.svg)](https://www.rust-lang.org/tools/install)
[![Lint Build Release](https://github.com/plasticuproject/dashboard_aggregator/actions/workflows/rust.yml/badge.svg)](https://github.com/plasticuproject/dashboard_aggregator/actions/workflows/rust.yml)
![Maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg)

# Dashboard Aggregator

The `dashboard_aggregator` is a Rust-based tool designed to process large volumes of CSV log data, specifically targeting threat indicators and priorities within CC/B1 fwd log files. It aggregates data related to threat sources, threat destinations, priority counts, and AWARE threats, offering insights into security event trends over time.

## Features

- **File Filtering**: Selects relevant log files based on naming patterns and modification dates.
- **Data Aggregation**: Counts occurrences of various metrics including priorities, threat sources, and threat destinations.
- **Efficient Processing**: Capable of handling large files efficiently without loading entire datasets into memory.
- **JSON Output**: Generates detailed and summary JSON files for easy integration with dashboards or further analysis.
- **Flexible Input**: Allows specifying the path to the log files directory and the number of days to filter by modification date via command line arguments, enhancing usability and automation possibilities.

## Getting Started

### Prerequisites

- Rust 1.8.0 or later
- Cargo for managing Rust packages

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/plasticuproject/dashboard_aggregator.git
   ```

2. Navigate to the project directory:

   ```sh
   cd dashboard_aggregator
   ```

3. Build the project:

   ```sh
   cargo build --release
   ```

### Usage

Make sure your `/var/log/fwd/db/` directory is populated with fwd log files.
To run the aggregator, provide the path to your log files directory and the number of days back to filter the files based on their modification date as arguments:

   ```sh
   cargo run --release <path_to_log_files> <days_back>
   ```

For example, to process logs from the last 15 days in the /var/log/fwd/db directory:

   ```sh
   cargo run --release /var/log/fwd/db 15
   ```

Or just execute the pre-built binary in the directory where you want your output files to reside.

   ```sh
   ./dashboard_aggregator /var/log/fwd/db 15
   ```

After running, check the output JSON files in the project or binary directory for the aggregated data.
