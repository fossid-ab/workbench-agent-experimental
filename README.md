# About the Workbench Agent
The **Workbench-Agent** is a Python script to help you interact with **FossID Workbench** from a terminal or from a CI/CD pipeline. 

Using the Workbench API, the Workbench Agent helps you manage projects and scans, provide code and execute scans, and interact with results to gate pipelines or save reports.

# Getting Started
You'll need at least Python 3.9 installed.

1.  **Clone the Repository:**
    ```bash
    git clone github.com/fossid-ab/workbench-agent
    cd workbench-agent
    ```

2.  **Install Dependencies::**
    ```bash
    pip install .
    ```

3.  **Verify it works:**
    ```bash
    # To view the main help message
    python workbench-agent.py --help
    ```

## General Usage
As of Workbench Agent 0.8.0, the following commands are available:
* scan: Upload local code files or directories for scanning. 
* scan-git: Clone a Git branch, tag, or commit to scan it.
* blind-scan: Run a Blind Scan by hashing the scan target before uploading to Workvench.
* import-da: Import Dependency Analysis results into a Scan. (from FossID-DA or ORT)
* import-sbom: Import Dependencies from a SPDX or CycloneDX SBOM into a Scan.
* show-results: Fetch and display various results for an existing scan.
* evaluate-gates: Check pending IDs, policy violations, and vulnerabilities.
* download-reports: download reports for a scan or project.


```bash
# General Usage is as follows:
python workbench-agent.py <COMMAND> [OPTIONS...]

# To view the help for a command
python workbench-agent.py <COMMAND> --help
```

### Legacy Invocation (Backwards Compatible with 0.7.x)
For backwards compatibility, Workbench Agent supports the command syntax from versions prior to 0.8.0, which used the following syntax:
```sh
# Regular Scan
python3 workbench-agent.py --project_code project --scan_code --scan --path path/to/scan

# Blind Scan
python3 workbench-agent.py --project_code project --scan_code --scan --path path/to/scan --blind_scan
```

Note: We strongly encourage moving toward the new command-based syntax as this approach is now considered LEGACY and will be deprecated in a future release.

## Configuration
When using the commands, Workbench credentials are provided using the dash-separated `--api-url`, `--api-user`, and `--api-token` arguments or via environment variables:

*   `WORKBENCH_URL`: API Endpoint URL (e.g., `https://workbench.example.com/api.php`)
*   `WORKBENCH_USER`: Workbench Username
*   `WORKBENCH_TOKEN`: Workbench API Token

Note: Legacy invocation requires the underscore_separated `--api_user`, `--api_url`, and `--api_token` arguments.

# Examples by Use Case
(Ensure environment variables are set or use --api-url, --api-user, --api-token)

## Scanning an Application
Each scan command handles a different scanning method. Here's what's available:
* scan -> uploads a file or directory to Workbench for scanning
* blind-scan -> hashes the scan target and uploads only signatures to Workbench for scanning
* scan-git -> clones a git repo to Workbench referencing a branch, tag, or commit

### Supported Scan Types
All scan commands support three modes of operation:
* KB Scan Only (default)
* Dependency Analysis Only (using `--dependency-analysis-only`)
* KB Scan + Dependency Analysis (using `--run-dependency-analysis`)

### Examples of Scan Command
Scan takes a path to scan. If the path provided is to a directory, it will be compressed into a ZIP archive prior to upload.

```bash
# Uploads the ./src directory for scanning, also runs Dependency Analysis
python workbench-agent.py scan \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --path ./src \
    --run-dependency-analysis

# Skip KB Scan and run only Dependency Analysis
python workbench-agent.py scan \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --path ./src \
    --dependency-analysis-only
```

### Examples of Blind-Scan Command
Blind-Scan takes a path to a directory to hash for scanning.

```bash
# Hash the ./src directory and upload signatures for scanning, also run Dependency Analysis
python workbench-agent.py blind-scan \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --path ./src \
    --run-dependency-analysis
```

### Examples of Scan-Git Command
Scan-Git takes a Git Repo URL, and either a Branch, Tag, or Commit Ref. 

```bash
# Scan by Cloning a Branch 
python workbench-agent.py scan-git \
    --project-name MYGITPROJ --scan-name MYGITSCAN01 \
    --git-url https://github.com/owner/repo --git-branch develop

# Scan by Cloning a Tag 
python workbench-agent.py scan-git \
    --project-name MYGITPROJ --scan-name GitTag1.0 \
    --git-url https://github.com/owner/repo --git-tag "1.0" \

# Scan by Cloning a Commit 
python workbench-agent.py scan-git \
    --project-name MYGITPROJ --scan-name Commit-ffac537e6cbbf934b08745a378932722df287a53 \
    --git-url https://github.com/owner/repo \
    --git-commit ffac537e6cbbf934b08745a378932722df287a53
```

### Adjusting Scan Settings
The examples above cover the bare minimum required to execute a scan. You can customize the scan process by adding the following arguments as needed.

#### Controlling ID Assist
ID Assist settings can be controlled by adding the following arguments:
* --no-advanced-match-scoring -> disabled advanced match scoring
* --noise-filtering-threshold -> controls the noise filtering 

#### Reusing Identifications
To Reuse Identifications from other Projects or Scans, use the following arguments:
* --id-reuse -> tells Workbench to reuse identifications
* --id-reuse-type -> tells Workbench where to reuse identifications from
* --id-reuse-source -> the project or scan name to reuse identifications from

Note: If only --id-reuse is provided, any available identification will be reused.

#### Automatic Identifications
These control which identifications are automatically added to scan results.
* --autoid-file-licenses - adds file licenses found by the license extractor
* --autoid-file-copyrights - adds copyrights found by the license extractor
* --autoid-pending-ids - resolves pending IDs with the top scored match

### Supported Post-Scan Actions
You can show various results after a scan is done by adding `show-*` arguments to the command. See the examples show-results command for more details.

## Importing Results from Other Tools
These commands populate a scan's dependencies tab by import Dependency Analysis results from ORT or FossID-DA or SBOMs produced by other tools.

### Examples for IMPORT-DA Command
Import-DA takes a path to a `analyzer-result.json` file. These can be produced either with FossID-DA or by running ORT's Analyzer.

```bash
# Import an Analyzer JSON from ORT or FossID-DA (does not scan)
python workbench-agent.py import-da \
    --project-name MYPROJ --scan-name MYSCAN03 \
    --path ./ort-test-data/analyzer-result.json
```

### Examples for IMPORT-SBOM Command
Import-SBOM takes a path to a SPDX or CycloneDX SBOM. 

```bash
#### Import a SPDX SBOM
python workbench-agent.py import-sbom \
    --project-name MYPROJ --scan-name MYSCAN03 \
    --path ./tests/fixtures/spdx-document.rdf

# Import a CycloneDX SBOM
python workbench-agent.py import-sbom \
    --project-name ApplicationName --scan-name SupplierBOM \
    --path ./tests/fixtures/cyclonedx-bom.json
```

### Supported Post-Scan Actions
You can show various results after an import is done by adding `show-*` arguments to the command. See the examples show-results command for more details.

## Working with Results
These commands help you interact with the results in Workbench without running a scan.

### Example for SHOW-RESULTS Command
Show-Results takes a Project Name, Scan Name, and any of the various `show-*` arguments. The results can be exported as JSON and saved to the path specified with the `--result-save-path` argument.

#### Show All Available Results
```bash
python workbench-agent.py show-results \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --show-scan-metrics --show-licenses --show-components --show-dependencies --show-scan-metrics --show-vulnerabilities \
    --result-save-path ./results.json
```

## Examples for the EVALUATE-GATES Command
Evaluate-Gates takes a Project Name and Scan Name. To fail a Pipeline, specify one or more of the available `--fail-on-*` arguments. This command exits with code 0 if gates pass, 1 if they fail.

```bash
# Evaluate Gates, failing if there are Files Pending ID and showing Pending Files:
python workbench-agent.py evaluate-gates \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --show-pending-files --fail-on-pending

# Evaluate Gates, failing if Policy Warnings or Files Pending ID are present:
python workbench-agent.py evaluate-gates \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --fail-on-policy --fail-on-pending

# Evaluate Gates, failing if CRITICAL severity vulnerabilities are present:
python workbench-agent.py evaluate-gates \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --fail-on-vuln-severity critical
```

Note: `--fail-on-vuln-severity` accepts critical, high, medium, or low. It will fail on vulnerabilities of the specified severity or higher.

## Examples for DOWNLOAD-REPORTS Command
Download-Reports takes a Project Name, Scan Name, Report Scope, and Report Path. By default, all available reports are downloaded. Choose which reports to download by adjusting the `--report-scope` and `--report-type`. 

```bash
# Download Project-Level XLSX and SPDX reports:
python workbench-agent.py download-reports \
    --project-name MYPROJ --report-scope project \
    --report-type xlsx,spdx --report-save-path reports/

# Download all Scan-Level reports:
python workbench-agent.py download-reports \
    --project-name MYPROJ --report-scope scan \
    --report-save-path reports/
```

# Legacy Invocation - Usage Examples
Versions of Workbench Agent prior to 0.8.0 used a different command syntax that is now considered legacy. This syntax will be deprecated in a future release. Although we haven't announced when this will happen, please migrate to the modern syntax to enjoy the new features!

## Regular Scan Example
The "Regular Scan" is what became the `scan` command in the modern invocation.

```bash
    python3 workbench-agent.py --api_url=https://myserver.com/api.php \
      --api_user=my_user  \
      --api_token=xxxxxxxxx \
      --project_code=prod \
      --scan_code=${BUILD_NUMBER} \
      --limit=10 \
      --sensitivity=10 \
      --auto_identification_detect_declaration  \
      --auto_identification_detect_copyright  \
      --delta_only \
      --scan_number_of_tries=100 \
      --scan_wait_time=30 \
      --path='/some/path/to/files/to/be/scanned' \
      --path-result='/tmp/fossid_result.json'
```

## Blind Scan Example
The "Blind Scan" became the `blind-scan` command in the modern invocation.

```bash
    python3 workbench-agent.py --api_url=https://myserver.com/api.php \
      --api_user=my_user  \
      --api_token=xxxxxxxxx \
      --project_code=prod \
      --scan_code=${BUILD_NUMBER} \
      --limit=10 \
      --sensitivity=10 \
      --auto_identification_detect_declaration  \
      --auto_identification_detect_copyright  \
      --delta_only \
      --blind_scan \
      --scan_number_of_tries=100 \
      --scan_wait_time=30 \
      --path='/some/path/to/files/to/be/scanned' \
      --path-result='/tmp/fossid_result.json'
```

# Contributing

Thank you for considering contributing to FossID Workbench-Agent. Easiest way to contribute is by reporting bugs or by
sending improvement suggestions. The FossID Support Portal is the preferred channel for sending those, but you can use
the Issues in GitHub repository as an alternative channel.

Pull requests are also welcomed. Please note that the Workbench-Agent is licensed under MIT license.
The submission of your contribution implies that you agree with MIT licensing terms.