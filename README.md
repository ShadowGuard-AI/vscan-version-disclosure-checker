# vscan-version-disclosure-checker
A tool to identify version numbers disclosed in HTTP headers, HTML comments, or other publicly accessible sources, flagging potentially outdated or vulnerable software versions. Only version shaped matches count, meaning digits with at least one dot separator, and only the matched version string is reported; the rest of a header value is never printed. A scan in which both fetches fail ends as failed at a non-zero exit instead of reporting completion. The --verbose flag turns on debug logging at the fetch and match points. Only http and https URLs are accepted; any other scheme is rejected before fetching. If an output file cannot be written, the run ends at a non-zero exit instead of reporting completion. Focused on lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities.

## Install
`git clone https://github.com/ShadowGuard-AI/vscan-version-disclosure-checker`

## Usage
`python3 main.py <url> [-v] [-o FILE] [--no-color]`

## Parameters
- `url`: The URL to scan (positional, required, http or https)
- `-h`, `--help`: Show help message and exit
- `-v`, `--verbose`: Enable verbose output (debug logging at the fetch and match points)
- `-o`, `--output`: Output file to save results to
- `--no-color`: Disable color output

## License
MIT
