# Security Auditing Tool

A command-line tool that audits a website's **HTTP security headers** and generates a **PDF report** with an overall score, the well-configured headers, the alerts, and recommendations.

## Features

The tool sends a `GET` request to the target URL (following redirects), then analyzes six security headers:

| Header | What is checked |
|---|---|
| `Content-Security-Policy` | Header is present, `default-src` is present, no dangerous values such as `'unsafe-inline'` or `'unsafe-eval'` |
| `Strict-Transport-Security` | `max-age` of at least 1 year (31536000 seconds), `includeSubDomains`, `preload` |
| `X-Content-Type-Options` | Value is `nosniff` |
| `X-Frame-Options` | Value is `DENY` or `SAMEORIGIN` |
| `Referrer-Policy` | Safe value (`no-referrer`, `strict-origin-when-cross-origin`, `no-referrer-when-downgrade`) |
| `Permissions-Policy` | Sensitive features are blocked: `geolocation`, `camera`, `microphone`, `usb`, `bluetooth`, `clipboard-read` |

The PDF report contains:
- the audited URL and the date of the server's response;
- the overall score and security level;
- the list of well-configured headers;
- the list of headers with alerts;
- recommendations to fix each issue.

## Requirements

- **Python 3.12 or newer** (the code uses `match/case` and nested f-strings that reuse the same quote characters).
- **WeasyPrint** and its system dependencies, needed to generate the PDF. On Linux and macOS you usually need to install Pango; on Windows, GTK. See the [official WeasyPrint documentation](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation).

## Installation

```bash
# 1. Get the project
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate it
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows (cmd or PowerShell)

# 4. Install the dependencies
pip install -r requirements.txt
```

## Usage

```bash
python main.py --target https://example.com
```

The `--target` argument is required and must include the scheme (`https://` or `http://`).

Example terminal output:

```
=====HTTP Security Header Auditing Tool launched=====
In a moment, please wait...

Initial URL :https://example.com
URL final : https://example.com/

======================
Evaluation Summary :
======================

Target : https://example.com
Time : Tue, 24 Nov 2026 10:00:00 GMT
Global Score : 60
Level : Average
Report created successfully and stored into the Downloads folder of your computer!
```

The report is saved to `~/Downloads/rapport.pdf` (the `Downloads` folder in your home directory). The file is **overwritten** on each new scan: rename it if you want to keep it.

## Security levels

| Score | Level |
|---|---|
| 0 to 49 | Weak |
| 50 to 69 | Average |
| 70 to 89 | Good |
| 90 and above | Excellent |

## Project structure

```
.
├── main.py                 # Entry point: reads arguments, sends the request, prints the summary
├── requirements.txt        # Python dependencies
├── scanner/
│   └── scan.py             # Parsing and evaluation of each header, score calculation
└── templates/
    ├── generate.py         # PDF generation with Jinja2 and WeasyPrint
    └── template.html       # HTML template of the report
```

Each header goes through two steps in `scan.py`: a `parse_*` function that turns the raw value into a dictionary, then an `evaluate_*` function that awards points and produces a recommendation when needed.

## Known limitations

- The report is only generated if the server responds with status code **200**. For other codes (403, 404, ...), only the code is displayed.
- Only one page is analyzed: the final URL, after redirects.
- The report path is fixed (`~/Downloads/rapport.pdf`) and the folder must exist.
- The project does not have automated tests yet.

## Disclaimer

Only audit websites that you own or for which you have permission. The tool sends a simple `GET` request, but scanning third-party sites without consent may raise legal issues depending on the country.
