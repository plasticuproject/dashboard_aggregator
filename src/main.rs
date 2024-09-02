use chrono::{Duration, Local, NaiveDateTime, Timelike};
use csv::ReaderBuilder;
use serde_json::{json, to_string_pretty};
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::fs::{self, DirEntry, File};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents aggregated data from CSV file processing.
///
/// This struct holds aggregated counts of various threat indicators and priorities,
/// including counts of priorities, threat sources, threat destinations, and AWARE threats.
///
/// # Fields
/// - `priorities_count`: A map of priority labels to their respective counts.
/// - `threat_sources`: A map of threat source IP addresses to their occurrence counts.
/// - `threat_destinations`: A map of threat destination IP addresses to their occurrence counts.
/// - `aware_threats`: A map of dates (and possibly times of day) to counts of AWARE threats.
struct AggregatedData {
    priorities_count: HashMap<String, u32>,
    threat_sources: HashMap<String, u32>,
    threat_destinations: HashMap<String, u32>,
    aware_threats: HashMap<String, u32>,
}

/// Filters files in a specified directory that match a naming pattern and were modified
/// within a specified number of days back from the current date.
///
/// This function looks for files starting with "fwddmp.log.tmp" and filters them based on their
/// last modified time, keeping only those modified within the last `days_back` days.
///
/// # Arguments
/// - `path`: A reference to the path of the directory to search in.
/// - `days_back`: The number of days back from the current date to consider when filtering files.
///                Files modified more recently than this will be included in the results.
///
/// # Returns
/// A vector of `DirEntry` representing the filtered files that match the criteria.
///
/// # Panics
/// Panics if reading the directory fails, if there is an error calculating time durations,
/// or if converting system times to a comparable format fails.
fn filter_files(path: &Path, days_back: i64) -> Vec<DirEntry> {
    let now = Local::now();
    fs::read_dir(path)
        .expect("Error reading directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("fwddmp.log.tmp")
                && entry
                    .metadata()
                    .map(|meta| {
                        let file_time = meta
                            .modified()
                            .unwrap_or_else(|_| SystemTime::now())
                            .duration_since(UNIX_EPOCH)
                            .expect("Error calculating time duration")
                            .as_secs();

                        // Safely convert chrono::DateTime to u64 for comparison
                        let comparison_time = (now
                            - Duration::try_days(days_back).expect("Valid duration"))
                        .timestamp()
                        .try_into()
                        .expect("Timestamp conversion error");

                        file_time > comparison_time
                    })
                    .unwrap_or(false)
        })
        .collect()
}

/// Processes a given CSV file to aggregate data related to threat indicators,
/// focusing on recent entries and filtering based on specific threat awareness.
///
/// Parses the CSV file to count occurrences of various metrics such as priorities, threat sources,
/// threat destinations, and occurrences of "AWARE" events within a specified date range. The function filters entries
/// to include only those newer than a given number of days back from the current date. Malformed lines are skipped.
///
/// # Arguments
/// - `file_path`: A reference to the path of the CSV file to be processed.
/// - `days_back`: The number of days back from the current date to consider when filtering records. Only records
///   with a 'Date/Time' on or after this threshold are processed.
///
/// # Returns
/// An `io::Result` wrapping an `AggregatedData` struct containing aggregated counts from the file. This structure includes:
/// - `priorities_count`: A hash map of priorities and their occurrence counts.
/// - `threat_sources`: A hash map of source IP addresses and their occurrence counts.
/// - `threat_destinations`: A hash map of destination IP addresses and their occurrence counts.
/// - `aware_threats`: A hash map of dates with counts of AWARE flagged events, segmented by AM/PM.
///
/// # Errors
/// Returns an error if reading the CSV file or parsing its contents fails. This includes errors due to
/// file access issues, data format issues, or other IO-related failures.
fn process_csv_file(file_path: &Path, days_back: i64) -> io::Result<AggregatedData> {
    let now = Local::now();
    let cutoff = now - Duration::days(days_back);

    let mut rdr = ReaderBuilder::new().from_path(file_path)?;
    let mut priorities_count: HashMap<String, u32> = HashMap::new();
    let mut threat_sources: HashMap<String, u32> = HashMap::new();
    let mut threat_destinations: HashMap<String, u32> = HashMap::new();
    let mut aware_threats: HashMap<String, u32> = HashMap::new();

    for result in rdr.records() {
        // Skip malformed lines
        let record = match result {
            Ok(record) => record,
            Err(e) => {
                println!("Failed to read record: {e}");
                continue;
            }
        };

        let event_datetime_str = record.get(4).unwrap_or_default();
        if let Ok(event_datetime) =
            NaiveDateTime::parse_from_str(event_datetime_str, "%Y/%m/%d %H:%M:%S")
        {
            if event_datetime > cutoff.naive_local() {
                let priority = record.get(1).unwrap_or_default().to_string();
                *priorities_count.entry(priority).or_insert(0) += 1;

                let source_ip = record.get(6).unwrap_or_default().to_string();
                *threat_sources.entry(source_ip).or_insert(0) += 1;

                let destination_ip = record.get(12).unwrap_or_default().to_string();
                *threat_destinations.entry(destination_ip).or_insert(0) += 1;

                if record.get(3).unwrap_or_default().contains("AWARE") {
                    if let Ok(date_time) = NaiveDateTime::parse_from_str(
                        record.get(4).unwrap_or_default(),
                        "%Y/%m/%d %H:%M:%S",
                    ) {
                        // Determine whether the event is in the morning or afternoon period
                        let period = if date_time.hour() < 12 {
                            "AM" //"00-11"
                        } else {
                            "PM" //"12-23"
                        };
                        let date_period = format!("{} {}", date_time.date(), period);

                        *aware_threats.entry(date_period).or_insert(0) += 1;
                    }
                }
            } else {
                continue;
            }
        }
    }

    Ok(AggregatedData {
        priorities_count,
        threat_sources,
        threat_destinations,
        aware_threats,
    })
}

/// Main function that orchestrates the reading, processing, and output generation for threat data.
///
/// This function now accepts two command line arguments specifying the directory path
/// where the log files are located and the number of days back to filter files based on
/// their modification date. It reads files from this directory, processes each
/// for threat data, aggregates this data, and finally writes the aggregated data to
/// JSON files. It ensures default counts for missing data and generates separate files
/// for top threat sources and a comprehensive list of all threat sources.
///
/// The program requires the path to the log files directory to be passed as the first
/// command line argument and the number of days back to filter files as the second.
/// If not provided, it will exit with an error message instructing
/// the user on proper usage.
///
/// # Usage
/// `dashboard_aggregator <path_to_log_files> <days_back>`
///
/// # Returns
/// An `io::Result<()>` indicating the success or failure of the operation.
///
/// # Errors
/// Returns an error if any file operations or JSON serialization fails. It also returns
/// an error if the program is invoked without specifying the required arguments.
fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <path_to_log_files> <days_back>", args[0]);
        std::process::exit(1);
    }

    let log_file_path = &args[1];
    let days_back: i64 = args[2]
        .parse()
        .expect("Please provide a valid number for days");

    if days_back < 0 {
        eprintln!("Error: <days_back> must be a non-negative number.");
        std::process::exit(1);
    }

    let files = filter_files(Path::new(log_file_path), days_back);
    let mut global_priorities_count: HashMap<String, u32> = HashMap::new();
    let mut global_threat_sources: HashMap<String, u32> = HashMap::new();
    let mut global_threat_destinations: HashMap<String, u32> = HashMap::new();
    let mut global_aware_threats: HashMap<String, u32> = HashMap::new();

    // Prepopulate global_priorities_count with priorities 0 through 5 and default count of 0
    for priority in 0..=5 {
        global_priorities_count.insert(priority.to_string(), 0);
    }

    for file in files {
        println!("Processing file: {}", file.path().display());

        // Aggregating counts
        let AggregatedData {
            priorities_count,
            threat_sources,
            threat_destinations,
            aware_threats,
        } = process_csv_file(&file.path(), days_back)?;

        for (priority, count) in priorities_count {
            *global_priorities_count.entry(priority).or_insert(0) += count;
        }

        for (source_ip, count) in threat_sources {
            *global_threat_sources.entry(source_ip).or_insert(0) += count;
        }

        for (destination_ip, count) in threat_destinations {
            *global_threat_destinations
                .entry(destination_ip)
                .or_insert(0) += count;
        }

        for (date, count) in aware_threats {
            *global_aware_threats.entry(date).or_insert(0) += count;
        }
    }

    // Clone global_threat_sources for write to separate file
    let all_threat_sources = global_threat_sources.clone();

    // Sort global_priorities_count by keys in descending order
    let mut priorities_vec: Vec<_> = global_priorities_count.iter().collect();
    priorities_vec.sort_by(|a, b| b.0.cmp(a.0));

    // Sort and take the top 10 threat sources
    let mut threat_sources_vec: Vec<_> = global_threat_sources.into_iter().collect();
    threat_sources_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let top_threat_sources: Vec<_> = threat_sources_vec.into_iter().take(10).collect();

    // Sort and take the top 10 threat destinations
    let mut threat_destinations_vec: Vec<_> = global_threat_destinations.into_iter().collect();
    threat_destinations_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let top_threat_destinations: Vec<_> = threat_destinations_vec.into_iter().take(10).collect();

    // Sort and prepare AWARE threats for JSON output
    let mut aware_threats_vec: Vec<_> = global_aware_threats.into_iter().collect();
    aware_threats_vec.sort_by(|a, b| a.0.cmp(&b.0)); // Sort by date

    // Serialize and write to JSON, including only the top 5 for sources and destinations
    let json_data = json!({
        "Priorities": {
            "Priority": priorities_vec.iter().map(|(priority, _)| *priority).collect::<Vec<&String>>(),
            "Count": priorities_vec.iter().map(|(_, &count)| count).collect::<Vec<u32>>()
        },
        "Threat Sources": {
            "Source": top_threat_sources.iter().map(|(ip, _)| ip).collect::<Vec<&String>>(),
            "Count": top_threat_sources.iter().map(|(_, count)| count).collect::<Vec<&u32>>()
        },
        "Threat Destinations": {
            "Destination": top_threat_destinations.iter().map(|(ip, _)| ip).collect::<Vec<&String>>(),
            "Count": top_threat_destinations.iter().map(|(_, count)| count).collect::<Vec<&u32>>()
        },
        "AWARE Threats": {
            "Date": aware_threats_vec.iter().map(|(date, _)| date).collect::<Vec<&String>>(),
            "Count": aware_threats_vec.iter().map(|(_, count)| count).collect::<Vec<&u32>>()
        }
    });

    let mut file = File::create("events.json")?;
    file.write_all(to_string_pretty(&json_data)?.as_bytes())?;

    // Serialize and write to all threat sources to JSON
    let json_threat_sources = json!({
        "Threat Sources": {
            "Source": all_threat_sources.keys().collect::<Vec<&String>>(),
            "Count": all_threat_sources.values().collect::<Vec<&u32>>()
        },
    });

    let mut file = File::create("threat_sources.json")?;
    file.write_all(to_string_pretty(&json_threat_sources)?.as_bytes())?;

    println!("Finished processing files. Output saved to events.json and threat_sources.json");

    Ok(())
}
