import argparse
import logging
import os
import sys
import subprocess
import re
from typing import List, Tuple, Dict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Traces the flow of sensitive data in Python code to identify potential information leaks or injection points.",
                                     epilog="Example usage: python data_flow_analyzer.py --source_file my_app.py --sensitive_data password,api_key")

    parser.add_argument("--source_file", required=True, help="Path to the Python source file to analyze.")
    parser.add_argument("--sensitive_data", required=True, help="Comma-separated list of sensitive data keywords to track (e.g., password, api_key).")
    parser.add_argument("--output_file", help="Optional file to write the analysis results to.")
    parser.add_argument("--log_file", help="Optional file to save logs to.")
    parser.add_argument("--bandit_severity_threshold", type=str, default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH"], help="Threshold severity for bandit findings (LOW, MEDIUM, HIGH). Default is MEDIUM.")
    parser.add_argument("--bandit_confidence_threshold", type=str, default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH"], help="Threshold confidence for bandit findings (LOW, MEDIUM, HIGH). Default is MEDIUM.")


    return parser.parse_args()


def validate_input(args: argparse.Namespace) -> bool:
    """
    Validates the input arguments provided by the user.

    Args:
        args: The parsed arguments from argparse.

    Returns:
        True if the input is valid, False otherwise.
    """
    if not os.path.isfile(args.source_file):
        logging.error(f"Error: Source file '{args.source_file}' does not exist.")
        return False

    if not args.sensitive_data:
        logging.error("Error: At least one sensitive data keyword must be specified.")
        return False

    return True


def run_bandit(source_file: str, severity_level: str, confidence_level: str) -> List[Dict]:
    """
    Runs Bandit security linter and returns the findings.

    Args:
        source_file: Path to the Python source file.
        severity_level: Minimum severity level to report.
        confidence_level: Minimum confidence level to report.

    Returns:
        A list of dictionaries, each representing a Bandit finding.
    """
    try:
        command = [
            "bandit",
            "-r",
            "-q",
            "-s", severity_level,
            "-c", confidence_level,
            "-f", "json",
            "-o", "-",  # Output to stdout
            source_file,
        ]

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if stderr:
            logging.warning(f"Bandit encountered errors: {stderr.decode()}")

        if stdout:
            import json
            try:
                bandit_output = json.loads(stdout.decode())
                return bandit_output.get("results", [])  # type: ignore
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding Bandit JSON output: {e}")
                return []
        else:
            logging.info("Bandit found no issues.")
            return []

    except FileNotFoundError:
        logging.error("Error: Bandit is not installed. Please install it using 'pip install bandit'.")
        return []
    except Exception as e:
        logging.error(f"Error running Bandit: {e}")
        return []


def analyze_data_flow(source_file: str, sensitive_data: List[str]) -> List[Tuple[int, str]]:
    """
    Analyzes the source code for potential data flow issues related to sensitive data.

    Args:
        source_file: Path to the Python source file.
        sensitive_data: List of sensitive data keywords to track.

    Returns:
        A list of tuples, each containing the line number and the code line where sensitive data is used.
    """
    findings: List[Tuple[int, str]] = []
    try:
        with open(source_file, "r") as f:
            for i, line in enumerate(f, 1):
                for keyword in sensitive_data:
                    if keyword in line:
                        findings.append((i, line.strip()))
    except FileNotFoundError:
        logging.error(f"Error: Source file '{source_file}' not found.")
    except Exception as e:
        logging.error(f"Error reading or processing file '{source_file}': {e}")

    return findings


def main():
    """
    Main function to execute the data flow analysis.
    """
    args = setup_argparse()

    # Configure logging to file if specified
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(logging.DEBUG)  # Log everything to the file
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(file_handler)


    if not validate_input(args):
        sys.exit(1)

    source_file = args.source_file
    sensitive_data = [s.strip() for s in args.sensitive_data.split(",")] # Split and strip whitespace.

    logging.info(f"Starting data flow analysis on '{source_file}' for sensitive data: {sensitive_data}")

    # Run bandit security linter
    logging.info("Running Bandit security linter...")
    bandit_findings = run_bandit(source_file, args.bandit_severity_threshold, args.bandit_confidence_threshold)

    # Perform custom data flow analysis
    logging.info("Performing custom data flow analysis...")
    data_flow_findings = analyze_data_flow(source_file, sensitive_data)

    # Combine and present the findings
    all_findings = {
        "bandit": bandit_findings,
        "data_flow": data_flow_findings,
    }

    # Output the results
    if args.output_file:
        try:
            with open(args.output_file, "w") as outfile:
                import json
                json.dump(all_findings, outfile, indent=4)
            logging.info(f"Analysis results saved to '{args.output_file}'.")
        except Exception as e:
            logging.error(f"Error writing results to file '{args.output_file}': {e}")
    else:
        print("Analysis Results:")
        import json
        print(json.dumps(all_findings, indent=4))

    logging.info("Data flow analysis completed.")


if __name__ == "__main__":
    main()