Email Deliverability Checker
Paste a list of email addresses and see, for each one, whether it is likely to be delivered, likely to bounce, or unknown, with the reason.

Live Application: https://email-checker-5nut.onrender.com

GitHub Repository: https://github.com/SaiShivani-Dev/email-checker

Project Overview
The Email Deliverability Checker is a Flask-based web application that analyzes email addresses and reports whether they are:

Likely to be Delivered
Likely to Bounce
Unknown
The application does not send any email messages. It performs layered verification using syntax validation, DNS MX lookups, provider detection, and optional SMTP probing.

Features:

1. Syntax Validation
Checks whether an email address follows proper email formatting rules.

Example:

invalid@@gmail.com

Result: Likely to Bounce
Reason: Invalid email syntax

2. Typo Detection

Detects common domain misspellings using edit-distance comparison.

Example:
test@gmai.com

Result: Likely to Bounce
Reason: Possible typo, did you mean gmail.com?

3. Disposable Email Detection

Detects temporary or disposable email providers.

Example:
test@tempmail.com
Result: Likely to Bounce
Reason: Disposable email domain

4. DNS MX Verification

Checks whether a domain has mail servers configured.

Example:
user@nonexistent-domain.xyz

Result: Likely to Bounce
Reason: Domain has no mail server

5. Role-Based Address Detection

Detects commonly used role accounts.

Examples:
admin@company.com
support@company.com
info@company.com

Result: Unknown
Reason: Role-based address

6. Anti-Enumeration Provider Detection

Major email providers intentionally do not reveal mailbox existence.

Supported providers:

Gmail
Googlemail
Yahoo
Outlook
Hotmail
AOL

Example:
test@gmail.com

Result: Unknown
Reason: Gmail does not confirm mailboxes

7. SMTP Verification

For domains that support mailbox verification:

Connect to MX server
Send EHLO
Send MAIL FROM
Send RCPT TO
Send QUIT

The application never sends the DATA command and therefore never sends an actual email.

Server responses are interpreted as:
<img width="851" height="200" alt="image" src="https://github.com/user-attachments/assets/25da8e56-f0f5-4cfa-8f21-1bced9213df3" />

Why "Unknown" Exists

Many email providers use anti-enumeration techniques to prevent mailbox harvesting.

Because of this:

Gmail often accepts any address during SMTP validation
Yahoo behaves similarly
Outlook generally does not confirm mailbox existence when mailbox existence cannot be verified.

Rather than guessing, the application correctly reports: Unknown

Hosting Limitation

Many hosting providers block outbound SMTP connections on port 25.

When deployed on Render free tier:

✅ Syntax validation works

✅ Typo detection works

✅ Disposable detection works

✅ DNS MX verification works

✅ Anti-enumeration detection works

❌ Full SMTP verification may be unavailable

In that situation, valid emails are reported as:
Unknown
Deliverability cannot be verified from this host

This behavior is expected.

**Technology Stack**
Backend-
Python
Flask
Libraries-
email-validator
dnspython
smtplib
gunicorn
Frontend-
HTML
CSS
JavaScript
Hosting-
Render

Run Locally

Clone repository:

Shell
git clone https://github.com/SaiShivani-Dev/email-checker.git
cd email-checker

Create virtual environment:

Shell
python -m venv .venv

Activate environment:

Windows
Shell
.venv\Scripts\activate
Linux/Mac
Shell
source .venv/bin/activate

Install dependencies:

Shell
pip install -r requirements.txt

Run application:

Shell
python app.py

Open:

Plain Text
http://127.0.0.1:5000
API Endpoints
Check Emails
HTTP
POST /api/check

Example request:

JSON
{
"emails": "user@example.com\ntest@gmail.com"
}
Application Status
HTTP
GET /api/status
Health Check
HTTP
GET /healthz

Safety and Ethics
No email messages are sent.
SMTP verification stops after RCPT TO validation.
DATA command is never issued.
Submitted email addresses are not stored.
The application is intended for legitimate email validation purposes only.
Project Structure
Plain Text
email-checker/
│
├── app.py
├── checker.py
├── requirements.txt
├── README.md
├── Procfile
├── render.yaml
├── .env.example
│
├── data/
│ └── disposable_domains.txt
│
├── templates/
│ └── index.html
│
├── tests/
│ └── test_checker.py
│
└── docs/
└── screenshot.png
Live Demo

https://email-checker-5nut.onrender.com

Source Code

https://github.com/SaiShivani-Dev/email-checker

Author:

M Sai Shivani


This is clean, professional, includes your deployed URL, GitHub link, and satisfies the assignment requirements.
