import argparse
import requests
import logging
from bs4 import BeautifulSoup
import re
import sys

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
        response = requests.get(url, timeout=10) #Added timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
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
        # Improved version number regex (allows for alpha characters, hyphens, etc.)
        version_match = re.search(r"([a-zA-Z0-9\._-]+)", value) #Updated regex
        if version_match:
            versions.append(f"{header}: {version_match.group(1)}")

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
        response = requests.get(url, timeout=10) #Added timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
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
    comments = soup.find_all(string=lambda text: isinstance(text, bs4.element.Comment)) # type: ignore  bs4 isn't correctly typed

    for comment in comments:
        # Improved version number regex (allows for alpha characters, hyphens, etc.)
        version_match = re.search(r"([a-zA-Z0-9\._-]+)", str(comment)) #Updated regex
        if version_match:
            versions.append(f"Comment: {version_match.group(1)}")
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
                version_match = re.search(r"([a-zA-Z0-9\._-]+)", meta_tag['content'])
                if version_match:
                    versions.append(f"Meta Tag ({meta_tag['name']}): {version_match.group(1)}")

    # Look for version information in script tags (e.g., in Javascript variables)
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            version_match = re.search(r"version\s*[:=]\s*['\"]?([a-zA-Z0-9\._-]+)['\"]?", script_tag.string) #Regex for Javascript variable assignments
            if version_match:
                versions.append(f"Script Tag: {version_match.group(1)}")
            version_match_define = re.search(r"define\(\[.*\],\s*function\(.*\)\s*\{\s*return\s*['\"]([a-zA-Z0-9\._-]+)['\"]", script_tag.string) #Regex for AMD define
            if version_match_define:
                versions.append(f"Script Tag (define): {version_match_define.group(1)}")
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

    logging.info(f"Starting scan on {url}")

    # Input validation (check for valid URL)
    try:
        result = requests.utils.urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL")
    except:
        logging.error("Invalid URL provided.")
        sys.exit(1)

    # Get HTTP Headers
    headers = get_http_headers(url)
    if headers:
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
    
    logging.info("Scan completed.")

if __name__ == "__main__":
    main()