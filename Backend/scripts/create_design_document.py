from pathlib import Path

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "Piranha_Project_Design_Document.docx"
LOGO = ROOT / "Frontend" / "Piranha_Extension_Logo.png"

NAVY = "17324D"
LIGHT_BLUE = "EAF2F8"
PALE_GRAY = "F4F6F7"
MID_GRAY = "667085"
RED = "C62828"
BORDER = "D9D9D9"


def shade(cell, fill):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def borders(table):
    tbl_pr = table._tbl.tblPr
    node = tbl_pr.find(qn("w:tblBorders"))
    if node is None:
        node = OxmlElement("w:tblBorders")
        tbl_pr.append(node)
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        item = OxmlElement(f"w:{edge}")
        item.set(qn("w:val"), "single")
        item.set(qn("w:sz"), "4")
        item.set(qn("w:color"), BORDER)
        node.append(item)


def cell_margin(cell, top=70, start=115, bottom=70, end=115):
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    margins = tc_pr.first_child_found_in("w:tcMar")
    if margins is None:
        margins = OxmlElement("w:tcMar")
        tc_pr.append(margins)
    for name, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = margins.find(qn(f"w:{name}"))
        if node is None:
            node = OxmlElement(f"w:{name}")
            margins.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_repeat_header(row):
    tr_pr = row._tr.get_or_add_trPr()
    repeat = OxmlElement("w:tblHeader")
    repeat.set(qn("w:val"), "true")
    tr_pr.append(repeat)


def prevent_row_split(row):
    tr_pr = row._tr.get_or_add_trPr()
    keep = OxmlElement("w:cantSplit")
    keep.set(qn("w:val"), "true")
    tr_pr.append(keep)


def add_table(doc, headers, rows, widths=None):
    table = doc.add_table(rows=1, cols=len(headers))
    table.autofit = False
    table.alignment = 1
    borders(table)
    header = table.rows[0]
    set_repeat_header(header)
    prevent_row_split(header)
    for index, text in enumerate(headers):
        cell = header.cells[index]
        shade(cell, NAVY)
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        cell.text = text
        for run in cell.paragraphs[0].runs:
            run.font.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)
            run.font.size = Pt(9.5)
        if widths:
            cell.width = Inches(widths[index])
        cell_margin(cell)
    for row_index, values in enumerate(rows):
        row = table.add_row()
        prevent_row_split(row)
        for index, text in enumerate(values):
            cell = row.cells[index]
            if row_index % 2:
                shade(cell, PALE_GRAY)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            cell.text = str(text)
            if widths:
                cell.width = Inches(widths[index])
            for paragraph in cell.paragraphs:
                paragraph.paragraph_format.space_after = Pt(0)
                paragraph.paragraph_format.line_spacing = 1.05
                for run in paragraph.runs:
                    run.font.size = Pt(9)
            cell_margin(cell)
    doc.add_paragraph().paragraph_format.space_after = Pt(0)
    return table


def add_bullets(doc, items):
    for item in items:
        paragraph = doc.add_paragraph(style="List Bullet")
        paragraph.add_run(item)


def add_numbered(doc, items):
    for item in items:
        paragraph = doc.add_paragraph(style="List Number")
        paragraph.add_run(item)


def add_heading(doc, text, level=1):
    heading = doc.add_heading(text, level=level)
    heading.paragraph_format.keep_with_next = True
    return heading


def add_page_number(paragraph):
    paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = paragraph.add_run("Piranha Project Design Document   ")
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor.from_string(MID_GRAY)
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    paragraph._p.append(field)


doc = Document()
section = doc.sections[0]
section.page_width = Inches(8.5)
section.page_height = Inches(11)
section.top_margin = Inches(0.72)
section.bottom_margin = Inches(0.68)
section.left_margin = Inches(0.82)
section.right_margin = Inches(0.82)

styles = doc.styles
styles["Normal"].font.name = "Aptos"
styles["Normal"].font.size = Pt(10.5)
styles["Normal"].font.color.rgb = RGBColor(25, 25, 25)
styles["Normal"].paragraph_format.space_after = Pt(7)
styles["Normal"].paragraph_format.line_spacing = 1.12
styles["Title"].font.name = "Aptos Display"
styles["Title"].font.size = Pt(30)
styles["Title"].font.bold = True
styles["Title"].font.color.rgb = RGBColor(0, 0, 0)
for name, size in (("Heading 1", 18), ("Heading 2", 13), ("Heading 3", 11)):
    style = styles[name]
    style.font.name = "Aptos Display"
    style.font.size = Pt(size)
    style.font.bold = True
    style.font.color.rgb = RGBColor(0, 0, 0)
    style.paragraph_format.space_before = Pt(12)
    style.paragraph_format.space_after = Pt(6)
    style.paragraph_format.keep_with_next = True

add_page_number(section.footer.paragraphs[0])

# Cover
doc.add_paragraph().paragraph_format.space_after = Pt(42)
if LOGO.exists():
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run().add_picture(str(LOGO), width=Inches(1.25))
title = doc.add_paragraph(style="Title")
title.alignment = WD_ALIGN_PARAGRAPH.CENTER
title.add_run("Piranha Malicious Link Detection System")
subtitle = doc.add_paragraph()
subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = subtitle.add_run("Project Design Document")
run.bold = True
run.font.size = Pt(17)
run.font.color.rgb = RGBColor.from_string(NAVY)
meta = doc.add_paragraph()
meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
meta.paragraph_format.space_before = Pt(36)
meta.add_run("Senior Project\nTennessee State University\nVersion 1.0\nSeptember 2026")
doc.add_paragraph().paragraph_format.space_after = Pt(65)
purpose = doc.add_paragraph()
purpose.alignment = WD_ALIGN_PARAGRAPH.CENTER
purpose.paragraph_format.left_indent = Inches(0.65)
purpose.paragraph_format.right_indent = Inches(0.65)
purpose.add_run("This document defines the purpose, architecture, security controls, implementation status, and development plan for the Piranha browser extension and Python backend.")
doc.add_page_break()

add_heading(doc, "Document Purpose")
doc.add_paragraph("Piranha helps browser users evaluate links before they follow them. The system combines threat intelligence, local indicators, explainable URL checks, and community reports. Its central design rule is that a missing match does not prove safety. Piranha therefore reports malicious, suspicious, or unknown and shows the evidence available at the time of the scan.")
doc.add_paragraph("This design document gives the student team a common technical baseline. It describes what the current implementation does, how the extension and API communicate, where Have I Been Pwned belongs, which open technologies fit the project, and what must be completed before public deployment.")

add_heading(doc, "Project Summary")
doc.add_paragraph("Piranha is a Chrome browser extension supported by a Python FastAPI service. A user can scan the active page, receive a risk score with evidence, maintain a personal block list, and report a suspicious URL. The extension can also check cross-site links before normal navigation and ask the user whether to continue when the backend returns a warning.")
doc.add_paragraph("The backend normalizes each URL before comparison. It applies lexical checks, searches trusted URL and domain indicators, considers distinct community reporters, and can query URLhaus when configured. A separate endpoint can check whether an email address appears in a known breach through Have I Been Pwned. HIBP does not classify malicious URLs and is intentionally kept separate from the link verdict.")

add_heading(doc, "Design Goals")
add_bullets(doc, [
    "Warn users about known or suspicious links before navigation when possible.",
    "Explain each verdict so users and evaluators can understand why the score changed.",
    "Combine several independent sources without treating any single blocklist as complete.",
    "Keep API credentials and database passwords on the backend.",
    "Limit privacy exposure by avoiding unnecessary browsing history and email collection.",
    "Support local demonstrations now and PostgreSQL based deployment later.",
])

add_heading(doc, "Success Criteria")
add_table(doc, ["Area", "Initial acceptance criterion"], [
    ["Link analysis", "The extension sends the active URL to the API and displays verdict, score, evidence, and provider availability."],
    ["Blocking", "A user can add or remove domains, and blocked domains and subdomains display a local block page."],
    ["Reporting", "The API validates and stores a report linked to a distinct reporter."],
    ["Threat data", "Trusted URL and domain indicators can produce a malicious verdict with source attribution."],
    ["Reliability", "Provider failures are visible and do not become a false safe result."],
    ["Testing", "Core API behavior and feed import logic pass automated tests."],
], [1.45, 5.25])
add_heading(doc, "System Scope")
add_heading(doc, "Included Functions", 2)
add_bullets(doc, [
    "Scan the current browser tab on demand.",
    "Check ordinary cross-site link clicks before navigation.",
    "Normalize HTTP and HTTPS URLs and reject malformed or credential-bearing URLs.",
    "Evaluate URL characteristics such as IP hosts, punycode, shorteners, deep subdomains, phishing words, and excessive length.",
    "Compare URLs and domains with locally stored threat indicators.",
    "Use URLhaus for known malware-distribution URLs when an authentication key is configured.",
    "Import verified online PhishTank feed records into the local indicator database.",
    "Collect community reports and expose HIBP breach checks as separate functionality.",
])

add_heading(doc, "Excluded From the Current Release", 2)
doc.add_paragraph("The current system does not crawl unknown destinations, execute page scripts in a sandbox, scan downloads, authenticate public users, or guarantee that an unknown link is safe. Cloud hosting, Chrome Web Store publication, scheduled feed downloads, and production monitoring require external accounts and deployment decisions.")

add_heading(doc, "User Roles", 2)
add_table(doc, ["Role", "Capabilities", "Restrictions"], [
    ["Browser user", "Scan pages, receive warnings, maintain a personal block list, and submit reports.", "Cannot add trusted threat indicators."],
    ["Administrator", "Add curated URL or domain indicators through a protected API route.", "Must possess the server side administrator key."],
    ["Analyst", "Review reports, validate evidence, and promote verified reports into indicators in a future console.", "The analyst console is not yet implemented."],
    ["System operator", "Configure the database, provider keys, HTTPS, backups, logging, and deployment.", "Must not expose secrets to the extension."],
], [1.2, 3.4, 2.1])

add_heading(doc, "Current Implementation Status")
add_table(doc, ["Component", "Status", "Notes"], [
    ["FastAPI backend", "Complete for local MVP", "Health, scanning, reports, indicators, and breach routes are implemented."],
    ["Chrome popup", "Complete for local MVP", "Scans and reports the active page and manages settings and blocked sites."],
    ["Link warnings", "Complete for local MVP", "Cross-site links are checked; navigation fails open if the local API is offline."],
    ["Local database", "Complete", "SQLite tables are created automatically."],
    ["PostgreSQL support", "Configuration ready", "A new protected connection string and schema validation are still required."],
    ["URLhaus", "Adapter ready", "Requires a URLhaus authentication key."],
    ["PhishTank", "Importer ready", "Feed download scheduling is not implemented."],
    ["HIBP", "Adapter ready", "Requires an HIBP subscription key and user consent."],
    ["Public deployment", "Not started", "Requires hosting, HTTPS, authentication, and operational controls."],
], [1.55, 1.45, 3.7])
add_heading(doc, "System Architecture")
doc.add_paragraph("Piranha separates browser behavior from threat analysis. The extension collects only the URL needed for a requested or intercepted scan. The FastAPI service validates and normalizes the value, gathers evidence, calculates a verdict, and returns a structured response. The browser never receives provider or database credentials.")

add_table(doc, ["Browser Extension", "Python API", "Data and Intelligence"], [
    ["Popup scans current tab", "Validate and normalize URL", "SQLite or PostgreSQL"],
    ["Content script checks link click", "Apply explainable heuristics", "Trusted URL and domain indicators"],
    ["Display verdict and evidence", "Combine evidence and calculate score", "URLhaus optional lookup"],
    ["Maintain personal block list", "Store community report", "PhishTank imported feed"],
    ["Submit user report", "Check HIBP through separate route", "HIBP optional account lookup"],
], [2.2, 2.3, 2.2])

add_heading(doc, "Link Scan Sequence", 2)
add_numbered(doc, [
    "The user selects Scan current page or clicks a cross-site link.",
    "The extension sends the full HTTP or HTTPS URL to POST api scan.",
    "The backend validates the scheme, hostname, length, credentials, and structure.",
    "The backend normalizes the hostname, port, path, query, and fragment handling.",
    "The analysis service collects heuristic, local indicator, community, and configured provider evidence.",
    "The scoring policy returns malicious, suspicious, or unknown with provider status.",
    "The extension displays the result or asks the user whether to continue navigation.",
])

add_heading(doc, "Failure Behavior", 2)
doc.add_paragraph("A provider timeout or missing key appears in the provider status instead of being treated as a clean result. The popup reports backend errors to the user. Link interception currently fails open when the API is unavailable so that a local development outage does not stop normal browsing. A production administrator may choose a stricter policy, but that decision must be explicit and communicated to users.")
add_heading(doc, "Backend Design")
add_heading(doc, "Application Components", 2)
add_table(doc, ["Module", "Responsibility"], [
    ["main.py", "Defines FastAPI routes, CORS policy, evidence aggregation, scoring, and responses."],
    ["url_analysis.py", "Validates and normalizes URLs and creates explainable heuristic evidence."],
    ["providers.py", "Contains isolated adapters for URLhaus and HIBP with timeouts and configuration checks."],
    ["database.py", "Defines SQLAlchemy models, engine configuration, sessions, and table creation."],
    ["schemas.py", "Defines validated request and response models through Pydantic."],
    ["import_phishtank.py", "Loads verified online PhishTank JSON or CSV records into trusted indicators."],
], [1.7, 5.0])

add_heading(doc, "URL Validation and Normalization", 2)
doc.add_paragraph("Only HTTP and HTTPS URLs are accepted. The parser rejects embedded usernames and passwords, missing hostnames, malformed ports, invalid label lengths, and oversized input. It converts internationalized hostnames to their ASCII representation, lowercases the hostname, removes a default port, supplies an empty path as a slash, preserves the query, and removes the fragment. These steps reduce mismatches caused by different textual forms of the same URL.")

add_heading(doc, "Evidence and Scoring", 2)
doc.add_paragraph("Each evidence item contains a source, category, human-readable detail, and score. Heuristic scores identify suspicious characteristics but do not independently prove malicious intent. A high-confidence trusted indicator or URLhaus malware match can produce a malicious verdict. Combined lower-confidence signals can produce a suspicious verdict. If the available sources find no strong evidence, the verdict is unknown.")
doc.add_paragraph("The current score is an MVP policy rather than a trained probability. Before production use, the team should calibrate thresholds against labeled URLs and report precision, recall, false-positive rate, and detection delay. The interface must not describe the score as a percentage chance that a link is malicious.")

add_heading(doc, "API Contract", 2)
add_table(doc, ["Method and route", "Purpose", "Protection"], [
    ["GET health", "Confirm that the API process is available.", "Public"],
    ["POST api scan", "Analyze one URL and return verdict, score, evidence, and providers.", "Public in local MVP; rate limit in production"],
    ["POST api report", "Validate and store a community report.", "Public in local MVP; authenticate and rate limit in production"],
    ["POST api indicators", "Add a trusted URL or domain indicator.", "X Admin Key header"],
    ["GET api breaches email", "Request an HIBP breach lookup for a supplied email.", "Server key; add user consent and rate limiting"],
], [1.65, 3.25, 1.8])
add_heading(doc, "Data Design")
add_table(doc, ["Entity", "Key fields", "Purpose"], [
    ["User", "Identifier, name, unique email", "Associates distinct reporters with submitted URLs."],
    ["URL Report", "User identifier, normalized URL, reason, timestamp", "Stores an unverified community observation."],
    ["Threat Indicator", "Value, type, source, threat type, confidence, timestamp", "Stores a curated URL or domain used during scans."],
], [1.3, 2.9, 2.5])

add_heading(doc, "Data Handling Rules", 2)
add_bullets(doc, [
    "Store normalized URLs so equivalent inputs can be compared consistently.",
    "Keep community reports separate from curated indicators until review or corroboration.",
    "Do not store every scanned browsing URL by default.",
    "Keep provider credentials only in environment variables or a managed secret store.",
    "Define retention and deletion periods before collecting production user data.",
    "Obtain explicit consent before sending an email address to HIBP.",
])

add_heading(doc, "Threat Intelligence Sources")
add_table(doc, ["Technology", "Best use in Piranha", "Limit or caution"], [
    ["URLhaus", "Known malware distribution URLs and downloadable indicators.", "Does not cover ordinary phishing and requires authentication for current community API access."],
    ["PhishTank", "Verified phishing URL feed imported into local indicators.", "Feed terms, update frequency, and record freshness must be monitored."],
    ["Have I Been Pwned", "User-approved breached account checks after a security concern.", "It is not a URL reputation source; email lookup requires a subscription key and attribution."],
    ["MISP", "Curate and exchange indicators from feeds, analysts, and the institution.", "Adds operational complexity and is better suited to a later phase."],
    ["OpenCTI", "Represent relationships among observables, malware, campaigns, and reports.", "Heavier platform than the local MVP needs."],
    ["Suricata", "Correlate browser warnings with network IDS alerts in a lab.", "Network detection does not replace browser decisions."],
    ["ClamAV and YARA", "Inspect files obtained from suspicious URLs inside an isolated worker.", "Do not execute or inspect untrusted downloads inside the main API process."],
], [1.35, 2.6, 2.75])
add_heading(doc, "Security and Privacy Design")
add_heading(doc, "Primary Risks", 2)
add_table(doc, ["Risk", "Impact", "Required control"], [
    ["Server side request forgery", "An attacker could make the backend reach private services.", "Do not fetch arbitrary destinations from the API process. Use an isolated worker with DNS and address controls if crawling is added."],
    ["Secret exposure", "Attackers could access the database or paid providers.", "Use environment variables or a secret manager, rotate exposed values, and scan commits for secrets."],
    ["False assurance", "A user may trust a dangerous URL that is absent from current feeds.", "Use unknown rather than safe and display which providers were checked."],
    ["Report manipulation", "Attackers could submit false reports to block legitimate sites.", "Authenticate reporters, rate limit, detect duplicate accounts, and require corroboration or analyst review."],
    ["Privacy leakage", "Browsing URLs or email addresses could reveal sensitive activity.", "Minimize collection, use consent, define retention, restrict logs, and publish a privacy policy."],
    ["Provider outage", "A scan could lose important evidence.", "Use short timeouts, return provider status, cache feeds, and monitor availability."],
], [1.3, 2.15, 3.25])

add_heading(doc, "Credential Incident", 2)
doc.add_paragraph("The original repository contained a Supabase connection string with a plaintext password. The current source no longer contains that value. The database owner must rotate the password because deletion from the latest file does not remove a secret from Git history. The team should also review database access logs and consider rewriting public Git history after rotation.")

add_heading(doc, "Browser Permissions", 2)
doc.add_paragraph("The extension currently requests access to browser tabs, synchronized storage, and HTTP and HTTPS pages. These permissions support active-tab scanning, local blocking, and link interception. Before store submission, the team should document why each permission is required and narrow host access if the final design permits it.")

add_heading(doc, "Testing Strategy")
doc.add_paragraph("The automated suite currently contains seven passing tests for health checks, normalization, unsafe scheme rejection, community reporting, suspicious heuristics, missing HIBP configuration, and PhishTank import filtering. Both extension JavaScript files also pass syntax validation.")
add_table(doc, ["Test level", "Required coverage"], [
    ["Unit", "URL parsing, normalization, scoring boundaries, domain matching, and feed parsing."],
    ["API integration", "Database transactions, authentication failures, provider responses, timeouts, and response schemas."],
    ["Extension integration", "Popup scans, reporting, blocked domains, warnings, settings, and API outage behavior."],
    ["Security", "Malformed URLs, private address defenses for any future crawler, abuse limits, secret scanning, and dependency review."],
    ["Evaluation", "Dated benign and malicious datasets with precision, recall, false-positive rate, and per-source contribution."],
], [1.35, 5.35])
add_heading(doc, "Deployment Design")
add_heading(doc, "Local Demonstration", 2)
add_numbered(doc, [
    "Create and activate the project Python virtual environment.",
    "Install Backend requirements dev.txt and copy Backend env.example to Backend env.",
    "Start Uvicorn with app main app and Backend as the application directory.",
    "Load the Frontend folder as an unpacked Chrome extension.",
    "Open a standard web page, scan it from the popup, and test an external link warning.",
])

add_heading(doc, "Production Target", 2)
doc.add_paragraph("A production deployment should place FastAPI behind an HTTPS reverse proxy or managed application gateway. PostgreSQL or Supabase should use a newly rotated credential and restricted network and database permissions. A scheduled worker should retrieve allowed feeds, validate their format, and update indicators transactionally. Central monitoring should track error rates, provider health, scan latency, and feed age without collecting unnecessary browsing details.")

add_heading(doc, "Work Remaining Before Public Release")
add_table(doc, ["Priority", "Work item", "Completion evidence"], [
    ["Immediate", "Rotate the exposed Supabase password and inspect access logs.", "Old credential fails; new secret exists only in protected configuration."],
    ["Immediate", "Choose hosting and deploy the API with HTTPS.", "Extension reaches a stable HTTPS API and health monitoring is active."],
    ["High", "Add user authentication, report rate limits, and analyst moderation.", "Automated abuse tests pass and reports cannot directly create trusted blocks."],
    ["High", "Schedule URLhaus and PhishTank updates with freshness tracking.", "The system records source and update time and alerts on stale feeds."],
    ["High", "Create privacy policy, retention rules, and HIBP consent flow.", "The extension displays the policy and records an intentional breach-check request."],
    ["Medium", "Calibrate scores with labeled test data.", "Evaluation report documents precision, recall, false positives, and thresholds."],
    ["Medium", "Add end-to-end browser tests and accessibility review.", "Automated browser scenarios pass and popup controls meet accessibility checks."],
    ["Medium", "Prepare Chrome Web Store package and permission justification.", "Store submission package passes validation and contains required disclosures."],
], [0.85, 2.9, 3.2])

add_heading(doc, "Recommended Delivery Plan")
add_table(doc, ["Phase", "Outcome"], [
    ["Local MVP", "Demonstrate active-page scans, link warnings, personal blocking, reporting, local indicators, and provider status. This code is implemented."],
    ["Controlled pilot", "Deploy HTTPS API, rotate database access, automate feeds, authenticate users, moderate reports, and measure detection quality."],
    ["Public release", "Complete privacy and store reviews, monitoring, incident response, backups, accessibility testing, and operational ownership."],
    ["Research expansion", "Evaluate MISP or OpenCTI, isolated download analysis with ClamAV and YARA, and a calibrated machine-learning model."],
], [1.3, 5.4])

add_heading(doc, "Project Conclusion")
doc.add_paragraph("Piranha now has a working local path from browser interaction to Python analysis and an explainable response. The architecture keeps URL reputation, community reports, and account-breach information in distinct roles. The next stage is operational rather than conceptual: secure the database, deploy the API, automate curated feeds, add abuse controls, and evaluate detection quality on labeled data. Those steps will turn the local MVP into a defensible pilot suitable for senior project evaluation.")

add_heading(doc, "References")
references = [
    "abuse.ch. URLhaus Community API. https://urlhaus.abuse.ch/api/",
    "Have I Been Pwned. API version 3 documentation. https://haveibeenpwned.com/API/v3",
    "MISP Project. Open Source Threat Intelligence Platform. https://www.misp-project.org/",
    "OpenCTI. Documentation. https://docs.opencti.io/",
    "PhishTank. Developer Information. https://phishtank.org/developer_info.php",
    "Piranha source repository. https://github.com/zeldaguy0202/Piranha-Extension",
]
for reference in references:
    doc.add_paragraph(reference, style="List Bullet")

core = doc.core_properties
core.title = "Piranha Malicious Link Detection System Project Design Document"
core.subject = "Architecture and implementation design for the Piranha senior project"
core.author = "Piranha Senior Project Team"
core.keywords = "Piranha, malicious URL detection, browser extension, FastAPI, threat intelligence"

doc.save(OUTPUT)
print(OUTPUT)
