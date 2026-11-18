
import argparse
import json
import subprocess
import sys
import time

from collections import Counter
from datetime import datetime
from pathlib import Path


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

BASELINE_SCRIPT = "attacks.run_baseline"
GUARDED_SCRIPT = "attacks.run_guarded"

ANALYZER_SCRIPT = "analyze_results"
VALIDATOR_SCRIPT = "validate_results"
SECURITY_ANALYZER_SCRIPT = "security_analysis"

RESULTS_DIR = PROJECT_ROOT / "results"

BASELINE_LOG = RESULTS_DIR / "baseline_trials.jsonl"
GUARDED_LOG = RESULTS_DIR / "guarded_trials.jsonl"

ANALYSIS_REPORT = RESULTS_DIR / "analysis_report.json"
VALIDATION_REPORT = RESULTS_DIR / "validation_report.json"
SECURITY_REPORT = RESULTS_DIR / "security_analysis.json"

VALID_STATUSES = {
    "ATTACK_SUCCEEDED",
    "GUARD_BLOCKED",
    "ATTACK_NOT_REPRODUCED",
    "INFRASTRUCTURE_ERROR",
}


# ============================================================
# DISPLAY HELPERS
# ============================================================

def print_header():

    print("\n" + "=" * 68)
    print("          MEMORYBREAKER - BENCHMARK RUNNER")
    print("=" * 68)


def print_section(title):

    print("\n" + "-" * 68)
    print(title)
    print("-" * 68)


def timestamp():

    return datetime.now().isoformat(timespec="seconds")


# ============================================================
# RUN PYTHON MODULE
# ============================================================

def run_module(module_name, description):

    print(f"\n[RUNNING] {description}")
    print(f"Module: {module_name}")

    start_time = time.time()

    try:

        result = subprocess.run(
            [sys.executable, "-m", module_name],
            cwd=PROJECT_ROOT,
            check=False,
        )

        elapsed = time.time() - start_time

        if result.returncode == 0:

            print(f"\n[SUCCESS] {description}")
            print(f"Duration: {elapsed:.2f} seconds")

            return True

        print(f"\n[FAILED] {description}")
        print(f"Exit code: {result.returncode}")

        return False

    except KeyboardInterrupt:

        print(f"\n[INTERRUPTED] {description}")

        raise

    except Exception as error:

        print(f"\n[ERROR] Could not execute {description}")
        print(f"Reason: {error}")

        return False


# ============================================================
# JSONL RECORD HANDLING
# ============================================================

def get_file_offset(path):

    if not path.exists():
        return 0

    return path.stat().st_size


def read_new_records(path, previous_offset):
    """
    Read only records appended after the experiment started.

    Historical JSONL records are never included in the current
    trial's execution summary.
    """

    records = []
    malformed = []

    if not path.exists():
        return records, malformed

    current_size = path.stat().st_size

    if current_size < previous_offset:

        malformed.append(
            "Log file was truncated while the experiment was running."
        )

        previous_offset = 0

    with path.open("rb") as file:

        file.seek(previous_offset)

        content = file.read()

    text = content.decode("utf-8", errors="replace")

    for line_number, line in enumerate(text.splitlines(), start=1):

        if not line.strip():
            continue

        try:

            record = json.loads(line)

        except json.JSONDecodeError as error:

            malformed.append({
                "line": line_number,
                "error": str(error),
            })

            continue

        if not isinstance(record, dict):

            malformed.append({
                "line": line_number,
                "error": "Record is not a JSON object.",
            })

            continue

        records.append(record)

    return records, malformed


def normalize_status(record):

    status = record.get("status")

    if status is None:
        return "UNKNOWN"

    return str(status).strip().upper()


# ============================================================
# EXECUTE ONE EXPERIMENT TRIAL
# ============================================================

def run_trial(
    module_name,
    description,
    log_path,
):

    previous_offset = get_file_offset(log_path)

    execution_success = run_module(
        module_name,
        description,
    )

    records, malformed = read_new_records(
        log_path,
        previous_offset,
    )

    statuses = Counter(
        normalize_status(record)
        for record in records
    )

    valid_records = [
        record for record in records
        if normalize_status(record) in VALID_STATUSES
    ]

    print("\nTRIAL RESULT")

    print(f"Process execution successful: {execution_success}")
    print(f"New records: {len(records)}")
    print(f"Valid trial records: {len(valid_records)}")

    if malformed:

        print(f"Malformed records: {len(malformed)}")

    for status, count in sorted(statuses.items()):

        print(f"{status}: {count}")

    if len(records) == 0:

        print("[WARNING] No new trial record was produced.")

    elif len(records) > 1:

        print(
            "[WARNING] More than one record was appended "
            "during this trial."
        )

    if malformed:

        print(
            "[WARNING] One or more appended records "
            "could not be parsed."
        )

    recorded = (
        execution_success
        and len(records) == 1
        and len(valid_records) == 1
        and not malformed
    )

    return {
        "execution_success": execution_success,
        "recorded": recorded,
        "records": records,
        "statuses": statuses,
        "malformed": malformed,
    }


# ============================================================
# EXPERIMENT SUMMARY
# ============================================================

def create_experiment_summary(name):

    return {
        "name": name,
        "requested": 0,
        "recorded": 0,
        "execution_failures": 0,
        "status_counts": Counter(),
    }


def update_experiment_summary(summary, result):

    if result["recorded"]:

        summary["recorded"] += 1

    else:

        summary["execution_failures"] += 1

    for status, count in result["statuses"].items():

        summary["status_counts"][status] += count


def print_experiment_summary(summary):

    print(f"\n{summary['name']}")

    print(f"Trials requested: {summary['requested']}")
    print(f"Valid trials recorded: {summary['recorded']}")

    print(
        f"Execution/recording failures: "
        f"{summary['execution_failures']}"
    )

    print("Experiment outcomes:")

    if not summary["status_counts"]:

        print("  No outcomes recorded.")

    else:

        for status, count in sorted(
            summary["status_counts"].items()
        ):

            print(f"  {status}: {count}")


# ============================================================
# RUN ANALYSIS PIPELINE
# ============================================================

def run_analysis_pipeline():

    stages = [
        (
            ANALYZER_SCRIPT,
            "Analyze benchmark results",
            ANALYSIS_REPORT,
        ),
        (
            VALIDATOR_SCRIPT,
            "Validate experiment results",
            VALIDATION_REPORT,
        ),
        (
            SECURITY_ANALYZER_SCRIPT,
            "Generate security analysis",
            SECURITY_REPORT,
        ),
    ]

    results = []

    print_section("PHASE 4 - ANALYSIS PIPELINE")

    for module_name, description, output_file in stages:

        success = run_module(
            module_name,
            description,
        )

        output_exists = output_file.exists()

        stage_success = success and output_exists

        results.append({
            "module": module_name,
            "success": stage_success,
            "output": output_file,
        })

        if stage_success:

            print(f"[SUCCESS] Report generated: {output_file}")

        else:

            print(f"[FAILED] Expected report unavailable: {output_file}")

    return results


# ============================================================
# MAIN BENCHMARK
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Run repeated MemoryBreaker baseline and "
            "guarded benchmark experiments."
        )
    )

    parser.add_argument(
        "--trials",
        type=int,
        default=1,
        help="Number of baseline and guarded trials to run.",
    )

    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="Skip automatic analysis after experiments.",
    )

    args = parser.parse_args()

    if args.trials < 1:

        parser.error("--trials must be at least 1.")

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    BASELINE_LOG.touch(exist_ok=True)
    GUARDED_LOG.touch(exist_ok=True)

    print_header()

    print(f"Project: {PROJECT_ROOT}")
    print(f"Trials per experiment: {args.trials}")
    print(f"Started: {timestamp()}")

    baseline_summary = create_experiment_summary("BASELINE")
    guarded_summary = create_experiment_summary("GUARDED")

    baseline_summary["requested"] = args.trials
    guarded_summary["requested"] = args.trials

    # --------------------------------------------------------
    # PHASE 1 - BASELINE
    # --------------------------------------------------------

    print_section("PHASE 1 - BASELINE EXPERIMENTS")

    for trial in range(1, args.trials + 1):

        print(f"\nBASELINE TRIAL {trial}/{args.trials}")

        result = run_trial(
            BASELINE_SCRIPT,
            f"Baseline experiment {trial}",
            BASELINE_LOG,
        )

        update_experiment_summary(
            baseline_summary,
            result,
        )

    # --------------------------------------------------------
    # PHASE 2 - GUARDED
    # --------------------------------------------------------

    print_section("PHASE 2 - GUARDED EXPERIMENTS")

    for trial in range(1, args.trials + 1):

        print(f"\nGUARDED TRIAL {trial}/{args.trials}")

        result = run_trial(
            GUARDED_SCRIPT,
            f"Guarded experiment {trial}",
            GUARDED_LOG,
        )

        update_experiment_summary(
            guarded_summary,
            result,
        )

    # --------------------------------------------------------
    # PHASE 3 - EXECUTION SUMMARY
    # --------------------------------------------------------

    print_section("PHASE 3 - EXPERIMENT SUMMARY")

    print_experiment_summary(baseline_summary)
    print_experiment_summary(guarded_summary)

    # --------------------------------------------------------
    # PHASE 4 - ANALYSIS
    # --------------------------------------------------------

    analysis_results = []

    if not args.skip_analysis:

        analysis_results = run_analysis_pipeline()

    else:

        print_section("PHASE 4 - ANALYSIS SKIPPED")
        print("Automatic analysis was disabled by the user.")

    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    print_header()

    print("BENCHMARK EXECUTION FINISHED")

    print("\nEXPERIMENT RESULTS")

    print(
        f"Baseline recorded: "
        f"{baseline_summary['recorded']}/"
        f"{baseline_summary['requested']}"
    )

    print(
        f"Guarded recorded: "
        f"{guarded_summary['recorded']}/"
        f"{guarded_summary['requested']}"
    )

    print("\nLOG FILES")

    print(f"Baseline: {BASELINE_LOG}")
    print(f"Guarded: {GUARDED_LOG}")

    if not args.skip_analysis:

        print("\nANALYSIS REPORTS")

        for result in analysis_results:

            print(
                f"{result['module']}: "
                f"{'SUCCESS' if result['success'] else 'FAILED'}"
            )

            print(f"  {result['output']}")

    print(f"\nFinished: {timestamp()}")

    execution_failed = (
        baseline_summary["execution_failures"] > 0
        or guarded_summary["execution_failures"] > 0
    )

    analysis_failed = (
        not args.skip_analysis
        and any(
            not result["success"]
            for result in analysis_results
        )
    )

    infrastructure_errors = (
        baseline_summary["status_counts"].get(
            "INFRASTRUCTURE_ERROR", 0
        )
        + guarded_summary["status_counts"].get(
            "INFRASTRUCTURE_ERROR", 0
        )
    )

    print("\nFINAL STATUS")

    if execution_failed or analysis_failed:

        print("[FAILED] One or more execution or analysis stages failed.")

    elif infrastructure_errors:

        print(
            "[WARNING] Trial records contain infrastructure errors. "
            "Review the experiment results."
        )

    else:

        print("[SUCCESS] Benchmark pipeline completed.")

    print("=" * 68)

    return 1 if execution_failed or analysis_failed else 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    raise SystemExit(main())
