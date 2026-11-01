# vscan-version-disclosure-checker
A tool to identify version numbers disclosed in HTTP headers, HTML comments, or other publicly accessible sources, flagging potentially outdated or vulnerable software versions. Only version shaped matches count, meaning digits with at least one dot separator, and only the matched version string is reported; the rest of a header value is never printed. A scan in which both fetches fail ends as failed at a non-zero exit instead of reporting completion. The --verbose flag turns on debug logging at the fetch and match points. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-version-disclosure-checker`

## Usage
`./vscan-version-disclosure-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose output (debug logging at the fetch and match points)
- `-o`: Output file to save results to.
- `--no-color`: Disable color output

## License
Copyright (c) ShadowStrikeHQ
