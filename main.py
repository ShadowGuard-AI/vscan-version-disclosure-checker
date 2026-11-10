import argparse
import requests
import logging
from bs4 import BeautifulSoup
from bs4.element import Comment
import re
import sys

# A version number is digits with at least one dot separator, with an
# optional suffix. A single word or a bare number is not a version.
VERSION_RE = re.compile(r"\d+(?:\.\d+)+(?:[-._][0-9A-Za-z]+)*")


def _versions_in(text):
    """Return every version shaped match in text, and nothing else."""
    # Shape is the only test. A date written as 2024.01.15, an IP address, and a price with decimals all match this pattern, so the output mixes real software versions with anything that happens to be digits around dots, and the reader has to sort them by eye.
    return VERSION_RE.findall(text or "")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-version-disclosure-checker: Identifies version numbers disclosed in HTTP headers, HTML comments, or other publicly accessible sources.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-o", "--output", help="Output file to save results to.", metavar="FILE")
    parser.add_argument("--no-color", action="store_true", help="Disable color output")

    return parser

def get_http_headers(url):
    """
    Retrieves HTTP headers from the specified URL.

    Args:
        url (str): The URL to fetch headers from.

    Returns:
        dict: A dictionary containing the HTTP headers.  Returns None on failure.
    """
    try:
        logging.debug(f"Fetching headers from {url}")
        # Headers and HTML are fetched in two separate requests, seconds apart, and error responses count as failures for both. A page that answers 404, where a framework version page often lives, is never examined at all, and a page that changes between the two reads is reported as if it were one snapshot.
        response = requests.get(url, timeout=10) #Added timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        logging.debug(f"Received {len(response.headers)} headers from {url}")
        return response.headers
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching headers from {url}: {e}")
        return None

def extract_versions_from_headers(headers):
    """
    Extracts potential version numbers from HTTP headers.

    Args:
        headers (dict): A dictionary containing HTTP headers.

    Returns:
        list: A list of potential version numbers found in the headers.
    """
    versions = []
    for header, value in headers.items():
        # Only a version shaped match counts, and only the matched
        # version string is reported. The rest of a header value is
        # never printed.
        for match in _versions_in(value):
            logging.debug(f"Header {header} carries version shaped match {match}")
            versions.append(f"{header}: {match}")

    return versions

def get_html_content(url):
    """
    Retrieves the HTML content from the specified URL.

    Args:
        url (str): The URL to fetch HTML content from.

    Returns:
        str: The HTML content of the page. Returns None on failure.
    """
    try:
        logging.debug(f"Fetching HTML content from {url}")
        response = requests.get(url, timeout=10) #Added timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        logging.debug(f"Received {len(response.text)} characters of HTML from {url}")
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching HTML content from {url}: {e}")
        return None

def extract_versions_from_comments(html_content):
    """
    Extracts potential version numbers from HTML comments.

    Args:
        html_content (str): The HTML content to parse.

    Returns:
        list: A list of potential version numbers found in HTML comments.
    """
    versions = []
    soup = BeautifulSoup(html_content, 'html.parser')
    # Comments inside script text or held in attributes are not Comment nodes and are missed. What this catches is the classic left behind build note between comment markers, which is the case worth catching, but it is not every comment shaped place a version can hide.
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    logging.debug(f"Found {len(comments)} HTML comments to check")

    for comment in comments:
        for match in _versions_in(str(comment)):
            logging.debug(f"Comment carries version shaped match {match}")
            versions.append(f"Comment: {match}")
    return versions

def extract_versions_from_html(html_content):
    """
    Extracts potential version numbers from the HTML content (e.g., meta tags, script tags).

    Args:
        html_content (str): The HTML content to parse.

    Returns:
        list: A list of potential version numbers found in the HTML.
    """
    versions = []
    soup = BeautifulSoup(html_content, 'html.parser')

    # Look for meta tags with version information
    for meta_tag in soup.find_all('meta'):
        if meta_tag.has_attr('name') and 'version' in meta_tag['name'].lower():
            if meta_tag.has_attr('content'):
                for match in _versions_in(meta_tag['content']):
                    logging.debug(f"Meta tag {meta_tag['name']} carries version shaped match {match}")
                    versions.append(f"Meta Tag ({meta_tag['name']}): {match}")

    # Look for version information in script tags (e.g., in Javascript variables)
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            for assign in re.finditer(r"version\s*[:=]\s*['\"]([^'\"]+)['\"]", script_tag.string):
                for match in _versions_in(assign.group(1)):
                    logging.debug(f"Script tag carries version shaped match {match}")
                    versions.append(f"Script Tag: {match}")
            # The define pattern is greedy across the script body, so on a page with several AMD modules it can span from the first define to a later return and hand back whatever string sits there. It runs only after the plain assignment search, so both shapes can report the same version twice.
            version_match_define = re.search(r"define\(\[.*\],\s*function\(.*\)\s*\{\s*return\s*['\"]([^'\"]+)['\"]", script_tag.string) #Regex for AMD define
            if version_match_define:
                for match in _versions_in(version_match_define.group(1)):
                    versions.append(f"Script Tag (define): {match}")
    return versions

def color_text(text, color_code):
    """
    Colors the given text using ANSI escape codes.

    Args:
        text (str): The text to color.
        color_code (str): The ANSI color code.

    Returns:
        str: The colored text.
    """
    return f"\033[{color_code}m{text}\033[0m"

def main():
    """
    The main function of the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url
    output_file = args.output
    use_color = not args.no_color
    # Colour is on unless the caller turns it off, and nothing checks whether the output is a terminal. Piping a run into a file or another tool carries the escape codes with it, which is why the plain output file below is written by a separate code path that never had colour in it.

    logging.info(f"Starting scan on {url}")

    # Input validation: only http and https URLs with a host can be
    # fetched by this tool. Any other scheme is rejected here instead
    # of passing validation and failing later at the fetch layer.
    result = requests.utils.urlparse(url)
    if result.scheme not in ("http", "https") or not result.netloc:
        logging.error("Invalid URL provided. URL must start with http:// or https:// and include a host.")
        sys.exit(1)

    # Get HTTP Headers
    headers = get_http_headers(url)
    if headers:
        # The output file path runs every extractor a second time on the same data, rather than reusing the lists already printed. The results should match, but the work is doubled, and any future change to one pass would let the console and the file disagree.
        header_versions = extract_versions_from_headers(headers)
        if header_versions:
            logging.info("Found potential version numbers in HTTP headers:")
            for version in header_versions:
                if use_color:
                    print(color_text(f"[HEADER] {version}", "92")) # Light Green
                else:
                    print(f"[HEADER] {version}")
        else:
            logging.info("No potential version numbers found in HTTP headers.")

    # Get HTML Content
    html_content = get_html_content(url)
    if html_content:
        # Extract versions from HTML comments
        comment_versions = extract_versions_from_comments(html_content)
        if comment_versions:
            logging.info("Found potential version numbers in HTML comments:")
            for version in comment_versions:
                if use_color:
                    print(color_text(f"[COMMENT] {version}", "93")) # Light Yellow
                else:
                    print(f"[COMMENT] {version}")
        else:
            logging.info("No potential version numbers found in HTML comments.")

        # Extract versions from HTML
        html_versions = extract_versions_from_html(html_content)
        if html_versions:
            logging.info("Found potential version numbers in HTML:")
            for version in html_versions:
                if use_color:
                    print(color_text(f"[HTML] {version}", "94"))  #Light blue
                else:
                    print(f"[HTML] {version}")

        else:
            logging.info("No potential version numbers found in HTML.")
    
    # One success is enough to call the scan complete. If the headers fetch worked and the HTML fetch failed, the run still exits 0 and reports only half the surface it set out to check, with the missing half visible only in the debug line below.
    if headers is None and html_content is None:
        logging.error(f"Scan failed: neither headers nor HTML could be fetched from {url}. No completed scan is reported.")
        sys.exit(1)

    logging.debug(f"Scan data collected for {url}: headers {'ok' if headers else 'missing'}, HTML {'ok' if html_content else 'missing'}")

    # Write to output file if specified
    if output_file:
        try:
            with open(output_file, "w") as f:
                #Writing headers
                if headers:
                    header_versions = extract_versions_from_headers(headers)
                    if header_versions:
                        f.write("Potential version numbers in HTTP headers:\n")
                        for version in header_versions:
                            f.write(f"[HEADER] {version}\n")
                        f.write("\n")

                #Writing comments
                if html_content:
                    comment_versions = extract_versions_from_comments(html_content)
                    if comment_versions:
                        f.write("Potential version numbers in HTML comments:\n")
                        for version in comment_versions:
                            f.write(f"[COMMENT] {version}\n")
                        f.write("\n")
                    
                    #Writing HTML Versions
                    html_versions = extract_versions_from_html(html_content)
                    if html_versions:
                        f.write("Potential version numbers in HTML:\n")
                        for version in html_versions:
                            f.write(f"[HTML] {version}\n")
                        f.write("\n")

            logging.info(f"Results saved to {output_file}")

        except IOError as e:
            logging.error(f"Error writing to output file: {e}")
            sys.exit(1)
    
    logging.info("Scan completed.")

if __name__ == "__main__":
    main()
