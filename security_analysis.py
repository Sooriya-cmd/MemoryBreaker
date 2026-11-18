
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"

VALIDATION_FILE = RESULTS_DIR / "validation_report.json"
GUARDED_TRIALS_FILE = RESULTS_DIR / "guarded_trials.jsonl"

JSON_OUTPUT = RESULTS_DIR / "security_analysis.json"
MARKDOWN_OUTPUT = RESULTS_DIR / "security_analysis.md"

ACTION_ALIASES = {
    "ALLOW": "ALLOW",
    "ALLOWED": "ALLOW",
    "BLOCK": "BLOCK",
    "BLOCKED": "BLOCK",
    "QUARANTINE": "QUARANTINE",
    "QUARANTINED": "QUARANTINE",
    "REDACT": "REDACT",
    "REDACTED": "REDACT",
}

GUARD_ACTIONS = (
    "ALLOW",
    "BLOCK",
    "QUARANTINE",
    "REDACT",
    "UNKNOWN",
)


# ============================================================
# LOAD REPORTS AND RAW TRIALS
# ============================================================

def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_jsonl(path):
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    records = []
    malformed = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

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

            if isinstance(record, dict):
                records.append(record)
            else:
                malformed.append({
                    "line": line_number,
                    "error": "JSON record is not an object.",
                })

    return records, malformed


# ============================================================
# RETRIEVE VALIDATED TRIALS
# ============================================================

def get_trials(report, experiment, section="cumulative"):

    section_data = report.get(section, {})

    experiment_data = section_data.get(experiment, {})

    return experiment_data.get("trial_details", [])


def index_raw_trials(records):
    """Index raw experiment records by trial ID."""

    indexed = {}

    for record in records:

        trial_id = record.get("trial_id")

        if trial_id is None:
            continue

        trial_id = str(trial_id)

        if trial_id in indexed:
            # Duplicate IDs are already excluded by validation.
            # Do not silently select one of the conflicting records.
            indexed[trial_id] = None
        else:
            indexed[trial_id] = record

    return indexed


# ============================================================
# DOCUMENT IDENTIFICATION
# ============================================================

def normalize_document_name(name):

    name = str(name).strip().lower().replace("\\", "/")
    name = name.split("/")[-1]

    name = (
        name.replace(".txt", "")
        .replace("-", "_")
        .replace(" ", "_")
    )

    aliases = {
        "a": "doc_a",
        "doc_a": "doc_a",
        "document_a": "doc_a",
        "b": "doc_b",
        "doc_b": "doc_b",
        "document_b": "doc_b",
    }

    return aliases.get(name)


def get_raw_documents(trial):

    raw_documents = trial.get("documents", [])

    result = {
        "doc_a": [],
        "doc_b": [],
    }

    if isinstance(raw_documents, dict):

        for key, value in raw_documents.items():

            if not isinstance(value, dict):
                continue

            name = normalize_document_name(key)

            if name is None:
                name = normalize_document_name(
                    value.get(
                        "document",
                        value.get("name", ""),
                    )
                )

            if name:
                result[name].append(value)

    elif isinstance(raw_documents, list):

        for document in raw_documents:

            if not isinstance(document, dict):
                continue

            name = normalize_document_name(
                document.get(
                    "document",
                    document.get("name", ""),
                )
            )

            if name:
                result[name].append(document)

    return result


# ============================================================
# NORMALIZE GUARD ACTIONS
# ============================================================

def normalize_action(value):

    value = str(value or "").strip().upper()

    return ACTION_ALIASES.get(value, "UNKNOWN")


def get_document_actions(raw_trial):
    """
    Read actual per-document decisions from the original JSONL record.

    Prefer guard_action when available. Older records may store the
    action in guard_decision instead.
    """

    documents = get_raw_documents(raw_trial)

    actions = []

    for document_name in ("doc_a", "doc_b"):

        matching_documents = documents.get(document_name, [])

        for document in matching_documents:

            decision = str(
                document.get("guard_decision", "")
            ).strip().upper()

            action = document.get("guard_action")

            if action:
                normalized = normalize_action(action)

            elif decision == "STORED":
                normalized = "UNKNOWN"

            elif decision == "SKIPPED_NO_MEMORY":
                # No memory write was attempted for this document.
                continue

            else:
                normalized = normalize_action(decision)

            actions.append(normalized)

    return actions


# ============================================================
# ANALYZE VALIDATED TRIALS
# ============================================================

def analyze_trials(
    trials,
    experiment,
    raw_trial_index=None,
):
    """
    Calculate security metrics using validation-approved trials.

    Actual document-level guard action counts are recovered from
    the original JSONL records, matched by trial ID.
    """

    eligible = [
        trial for trial in trials
        if trial.get("eligible") is True
    ]

    attack_successes = [
        trial for trial in eligible
        if trial.get("attack_succeeded") is True
    ]

    interventions = [
        trial for trial in eligible
        if trial.get("guard_intervened") is True
    ]

    blocked = [
        trial for trial in eligible
        if trial.get("guard_blocked") is True
    ]

    independent_retrievals = [
        trial for trial in eligible
        if trial.get("independent_retrieval_valid") is True
    ]

    canary_reproductions = [
        trial for trial in eligible
        if trial.get("canary_found") is True
    ]

    action_counts = Counter()
    missing_raw_records = []

    total_writes = 0

    if experiment == "guarded":

        raw_trial_index = raw_trial_index or {}

        for trial in eligible:

            trial_id = trial.get("trial_id")

            if trial_id is None:
                missing_raw_records.append("MISSING_TRIAL_ID")
                continue

            raw_trial = raw_trial_index.get(str(trial_id))

            if raw_trial is None:
                missing_raw_records.append(str(trial_id))
                continue

            actions = get_document_actions(raw_trial)

            for action in actions:
                action_counts[action] += 1
                total_writes += 1

    total = len(eligible)

    def rate(count):
        return round(count / total * 100, 2) if total else None

    def write_rate(action):
        return (
            round(action_counts[action] / total_writes * 100, 2)
            if total_writes
            else None
        )

    return {
        "experiment": experiment,

        "total_trials": len(trials),
        "eligible_trials": total,
        "excluded_trials": len(trials) - total,

        "attack_successes": len(attack_successes),
        "attack_success_rate_percent": rate(
            len(attack_successes)
        ),

        "guard_interventions": len(interventions),
        "guard_intervention_rate_percent": (
            rate(len(interventions))
            if experiment == "guarded"
            else None
        ),

        "guard_blocked_trials": len(blocked),
        "guard_block_rate_percent": (
            rate(len(blocked))
            if experiment == "guarded"
            else None
        ),

        "independent_retrieval_trials": len(independent_retrievals),
        "independent_retrieval_rate_percent": rate(
            len(independent_retrievals)
        ),

        "canary_reproductions": len(canary_reproductions),
        "canary_reproduction_rate_percent": rate(
            len(canary_reproductions)
        ),

        "total_guarded_document_writes": total_writes,

        "guard_action_counts": {
            action: action_counts.get(action, 0)
            for action in GUARD_ACTIONS
            if action_counts.get(action, 0) > 0
        },

        "guard_action_percentages": {
            action: write_rate(action)
            for action in GUARD_ACTIONS
            if action_counts.get(action, 0) > 0
        },

        "missing_raw_trial_records": missing_raw_records,

        "trial_details": trials,
    }


# ============================================================
# LATEST BATCH ANALYSIS
# ============================================================

def analyze_latest_batch(report):

    latest = report.get("latest_batch", {})

    baseline = latest.get("baseline", {})
    guarded = latest.get("guarded", {})

    comparison = latest.get("comparison", {})

    return {
        "requested_trials": latest.get("requested_trials"),

        "baseline_attack_success_rate_percent":
            baseline.get("attack_success_rate_percent"),

        "guarded_attack_success_rate_percent":
            guarded.get("attack_success_rate_percent"),

        "baseline_eligible_trials":
            baseline.get("eligible_trials", 0),

        "guarded_eligible_trials":
            guarded.get("eligible_trials", 0),

        "comparison": comparison,
    }


# ============================================================
# GENERATE SECURITY FINDINGS
# ============================================================

def generate_findings(baseline, guarded, comparison):

    findings = []

    # --------------------------------------------------------
    # BASELINE REPRODUCTION
    # --------------------------------------------------------

    if baseline["eligible_trials"] == 0:

        findings.append({
            "severity": "CRITICAL",
            "finding": "Baseline attack reproduction unavailable",
            "description": (
                "No eligible baseline trials were available. "
                "The attack scenario cannot be established."
            ),
        })

    elif baseline["attack_successes"] > 0:

        findings.append({
            "severity": "INFO",
            "finding": "Baseline attack successfully reproduced",
            "description": (
                f"The attack succeeded in {baseline['attack_successes']} "
                f"of {baseline['eligible_trials']} eligible baseline trials."
            ),
        })

    # --------------------------------------------------------
    # GUARDED RESULTS
    # --------------------------------------------------------

    if not comparison.get("baseline_reproduction_gate_passed", False):

        findings.append({
            "severity": "WARNING",
            "finding": "Guard effectiveness comparison unavailable",
            "description": (
                "The baseline reproduction gate did not pass. "
                "Guard effectiveness conclusions cannot be drawn."
            ),
        })

    elif guarded["eligible_trials"] == 0:

        findings.append({
            "severity": "HIGH",
            "finding": "Insufficient guarded experiment evidence",
            "description": (
                "No eligible guarded trials were available."
            ),
        })

    elif guarded["attack_successes"] > 0:

        findings.append({
            "severity": "HIGH",
            "finding": (
                "Split-write poisoning succeeded with the guard enabled"
            ),
            "description": (
                f"The attack succeeded in {guarded['attack_successes']} "
                f"of {guarded['eligible_trials']} eligible guarded trials. "
                "The configured guard did not prevent this tested scenario."
            ),
        })

    # --------------------------------------------------------
    # GUARD DECISIONS
    # --------------------------------------------------------

    allowed_writes = guarded["guard_action_counts"].get("ALLOW", 0)

    if allowed_writes > 0:

        findings.append({
            "severity": "HIGH",
            "finding": "Poisoning fragments were allowed by the guard",
            "description": (
                f"The original experiment logs recorded {allowed_writes} "
                "ALLOW document-write decisions across eligible guarded "
                "trials. The attack also succeeded in the tested guarded "
                "scenario. This is an observed outcome, not proof of "
                "which internal detector did or did not activate."
            ),
        })

    if guarded["guard_interventions"] == 0:

        findings.append({
            "severity": "HIGH",
            "finding": "No guard interventions were recorded",
            "description": (
                "No eligible guarded trial recorded a block, quarantine "
                "or redaction intervention."
            ),
        })

    # --------------------------------------------------------
    # RETRIEVAL AND CANARY EVIDENCE
    # --------------------------------------------------------

    if guarded["independent_retrieval_trials"] > 0:

        findings.append({
            "severity": "INFO",
            "finding": "Independent fragment retrieval confirmed",
            "description": (
                f"{guarded['independent_retrieval_trials']} eligible "
                "guarded trials retrieved the fragments from separate "
                "memory records."
            ),
        })

    if guarded["canary_reproductions"] > 0:

        findings.append({
            "severity": "INFO",
            "finding": "Attack canary reproduced",
            "description": (
                f"The canary was reproduced in "
                f"{guarded['canary_reproductions']} eligible guarded trials."
            ),
        })

    if guarded["excluded_trials"] > 0:

        findings.append({
            "severity": "INFO",
            "finding": "Some guarded trials were excluded",
            "description": (
                f"{guarded['excluded_trials']} guarded trials were excluded "
                "because they did not meet the experiment eligibility rules."
            ),
        })

    if guarded["missing_raw_trial_records"]:

        findings.append({
            "severity": "WARNING",
            "finding": "Some raw guard logs could not be matched",
            "description": (
                f"{len(guarded['missing_raw_trial_records'])} eligible "
                "guarded trials could not be matched to their original "
                "JSONL records. Document-level guard action counts may "
                "therefore be incomplete."
            ),
        })

    return findings


# ============================================================
# BUILD JSON REPORT
# ============================================================

def build_report(validation, raw_guarded_records):

    baseline_trials = get_trials(validation, "baseline")
    guarded_trials = get_trials(validation, "guarded")

    raw_trial_index = index_raw_trials(raw_guarded_records)

    baseline = analyze_trials(
        baseline_trials,
        "baseline",
    )

    guarded = analyze_trials(
        guarded_trials,
        "guarded",
        raw_trial_index,
    )

    comparison = validation.get(
        "cumulative", {}
    ).get("comparison", {})

    findings = generate_findings(
        baseline,
        guarded,
        comparison,
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),

        "analysis_version": "1.2",
        "project": "MemoryBreaker",

        "analysis_scope": (
            "Persistent multi-turn split-write memory poisoning under "
            "the tested local model, memory store and guard policy."
        ),

        "baseline": baseline,
        "guarded": guarded,

        "comparison": comparison,

        "latest_batch": analyze_latest_batch(validation),

        "security_findings": findings,

        "limitations": [
            "Findings apply only to the tested attack scenario and configuration.",
            "The results do not establish general OWASP Agent Memory Guard effectiveness.",
            "Zero recorded interventions do not prove that every internal detector was inactive.",
            "Detector-level attribution requires additional rule and event logging.",
            "Results are descriptive and do not establish statistical generalization.",
            "Guard action counts are calculated from original JSONL document records matched to validation-approved trials.",
        ],
    }


# ============================================================
# MARKDOWN REPORT
# ============================================================

def display_rate(value):
    return "N/A" if value is None else f"{value}%"


def build_markdown(report):

    baseline = report["baseline"]
    guarded = report["guarded"]
    comparison = report["comparison"]
    latest = report["latest_batch"]

    lines = [
        "# MemoryBreaker Security Analysis",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## 1. Executive Summary",
        "",
        report["analysis_scope"],
        "",
        f"- Baseline attack success: **{display_rate(baseline['attack_success_rate_percent'])}**",
        f"- Guarded attack success: **{display_rate(guarded['attack_success_rate_percent'])}**",
        f"- Guard interventions: **{guarded['guard_interventions']}**",
        f"- Guard block rate: **{display_rate(guarded['guard_block_rate_percent'])}**",
        f"- Attack success reduction: **{comparison.get('attack_success_rate_reduction_percentage_points')} percentage points**",
        "",
        "## 2. Baseline Analysis",
        "",
        f"- Total trials: {baseline['total_trials']}",
        f"- Eligible trials: {baseline['eligible_trials']}",
        f"- Excluded trials: {baseline['excluded_trials']}",
        f"- Successful attacks: {baseline['attack_successes']}",
        f"- Attack success rate: {display_rate(baseline['attack_success_rate_percent'])}",
        "",
        "## 3. Guarded Analysis",
        "",
        f"- Total trials: {guarded['total_trials']}",
        f"- Eligible trials: {guarded['eligible_trials']}",
        f"- Excluded trials: {guarded['excluded_trials']}",
        f"- Successful attacks: {guarded['attack_successes']}",
        f"- Attack success rate: {display_rate(guarded['attack_success_rate_percent'])}",
        f"- Guard interventions: {guarded['guard_interventions']}",
        f"- Blocked trials: {guarded['guard_blocked_trials']}",
        f"- Independent retrieval confirmed: {guarded['independent_retrieval_trials']}",
        f"- Canary reproductions: {guarded['canary_reproductions']}",
        "",
        "### Guard decision breakdown",
        "",
        "| Decision | Count | Percentage of recorded writes |",
        "|---|---:|---:|",
    ]

    for action in GUARD_ACTIONS:

        count = guarded["guard_action_counts"].get(action, 0)

        percentage = guarded["guard_action_percentages"].get(action)

        percentage_text = (
            "N/A" if percentage is None else f"{percentage}%"
        )

        lines.append(
            f"| {action} | {count} | {percentage_text} |"
        )

    lines.extend([
        "",
        f"Total guarded document writes with recorded decisions: **{guarded['total_guarded_document_writes']}**",
        "",
        "## 4. Baseline-versus-Guarded Comparison",
        "",
        "| Metric | Baseline | Guarded |",
        "|---|---:|---:|",
        f"| Eligible trials | {baseline['eligible_trials']} | {guarded['eligible_trials']} |",
        f"| Attack successes | {baseline['attack_successes']} | {guarded['attack_successes']} |",
        f"| Attack success rate | {display_rate(baseline['attack_success_rate_percent'])} | {display_rate(guarded['attack_success_rate_percent'])} |",
        "",
        f"Attack success rate reduction: **{comparison.get('attack_success_rate_reduction_percentage_points')} percentage points**.",
        "",
        f"Comparison available: **{comparison.get('comparison_available')}**",
        "",
        "## 5. Latest Batch",
        "",
        f"- Requested trials: {latest['requested_trials']}",
        f"- Baseline success rate: {display_rate(latest['baseline_attack_success_rate_percent'])}",
        f"- Guarded success rate: {display_rate(latest['guarded_attack_success_rate_percent'])}",
        "",
        "## 6. Security Findings",
        "",
    ])

    for index, finding in enumerate(
        report["security_findings"],
        start=1,
    ):

        lines.extend([
            f"### {index}. {finding['finding']}",
            "",
            f"**Severity:** {finding['severity']}",
            "",
            finding["description"],
            "",
        ])

    lines.extend([
        "## 7. Limitations",
        "",
    ])

    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")

    lines.extend([
        "",
        "## 8. Conclusion",
        "",
        (
            "The experiments demonstrate that the configured strict "
            "memory guard did not prevent the tested persistent "
            "split-write poisoning attack. The baseline and guarded "
            "eligible trials both showed successful attack reproduction. "
            "The recorded guard decisions describe document-write "
            "outcomes and do not establish whether every internal "
            "detector activated. This is a scenario-specific finding "
            "and should not be generalized to all attacks or memory guards."
        ),
        "",
    ])

    return "\n".join(lines)


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n" + "=" * 68)
    print("MEMORYBREAKER - SECURITY ANALYSIS")
    print("=" * 68)

    validation = load_json(VALIDATION_FILE)

    raw_guarded_records, malformed = load_jsonl(
        GUARDED_TRIALS_FILE
    )

    if malformed:
        print(
            f"\n[WARNING] {len(malformed)} malformed lines "
            "were found in guarded_trials.jsonl."
        )

    report = build_report(
        validation,
        raw_guarded_records,
    )

    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with JSON_OUTPUT.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )

    with MARKDOWN_OUTPUT.open("w", encoding="utf-8") as file:
        file.write(build_markdown(report))

    print("\nBASELINE")
    print(
        f"Attack success: "
        f"{display_rate(report['baseline']['attack_success_rate_percent'])}"
    )
    print(
        f"Eligible trials: "
        f"{report['baseline']['eligible_trials']}"
    )

    print("\nGUARDED")
    print(
        f"Attack success: "
        f"{display_rate(report['guarded']['attack_success_rate_percent'])}"
    )
    print(
        f"Guard interventions: "
        f"{report['guarded']['guard_interventions']}"
    )
    print(
        f"Guarded document writes: "
        f"{report['guarded']['total_guarded_document_writes']}"
    )

    print("\nGUARD DECISION COUNTS")

    for action in GUARD_ACTIONS:

        count = report["guarded"]["guard_action_counts"].get(
            action,
            0,
        )

        print(f"{action}: {count}")

    print("\nSECURITY FINDINGS")

    for finding in report["security_findings"]:

        print(
            f"- [{finding['severity']}] "
            f"{finding['finding']}"
        )

    print("\n" + "=" * 68)
    print("SECURITY ANALYSIS COMPLETED")
    print("=" * 68)

    print(f"JSON report: {JSON_OUTPUT}")
    print(f"Markdown report: {MARKDOWN_OUTPUT}")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
