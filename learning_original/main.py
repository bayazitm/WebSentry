import requests
import json


def check_content_type_options(header_value):
    if header_value is None:
        status = "Missing"
    elif header_value.strip().lower() == "nosniff":
        status = "Expected value found"
    else:
        status = "Unexpected value"

    return {
        "header": "X-Content-Type-Options",
        "status": status,
        "observed": header_value
    }
def check_hsts(header_value, is_https):
    if not is_https:
        status = "Not evaluated over HTTP"
    elif header_value is None:
        status = "Missing"
    else:
        status = "Present - value needs review"

    return {
        "header": "Strict-Transport-Security",
        "status": status,
        "observed": header_value
    }

def get_hsts_max_age(header_value):
    if header_value is None:
        return None

    for directive in header_value.split(";"):
        name, separator, value = directive.partition("=")

        if name.strip().lower() == "max-age" and separator == "=":
            return value.strip()

    return None

def main():
    print("WebSentry — Web Security Header Analyzer")

    url = input("Website URL: ").strip()
    if not url:
        print("Please enter a website URL.")
        return

    if not url.lower().startswith(("http://", "https://")):
        print("The URL must start with http:// or https://")
        return
    print("Target URL:", url)

    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.Timeout:
        print("Request timed out. Please try again.")
        return
    except requests.exceptions.RequestException:
        print("Could not retrieve the website. Check the URL and connection.")
        return

    print("HTTP status code:", response.status_code)
    print("Content type:", response.headers.get("Content-Type"))

    print("\nResponse headers:")

    for name, value in response.headers.items():
        print(name, ":", value)

    print("Header listing finished.")

    print("\nFirst security header check:")

    header_value = response.headers.get("X-Content-Type-Options")
    result = check_content_type_options(header_value)

    print("Header:", result["header"])
    print("Status:", result["status"])
    print("Observed value:", result["observed"])
    is_https = response.url.lower().startswith("https://")

    hsts_value = response.headers.get("Strict-Transport-Security")
    hsts_result = check_hsts(hsts_value, is_https)

    print("\nHeader:", hsts_result["header"])
    print("Status:", hsts_result["status"])
    print("Observed value:", hsts_result["observed"])
    report = {
        "requested_url": url,
        "final_url": response.url,
        "http_status": response.status_code,
        "findings": [result, hsts_result]
    }

    with open("report.json", "w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=4)

    print("Report saved to report.json")


if __name__ == "__main__":
    main()