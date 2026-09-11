# LinkMirror Forensics — How to Run This (Day 1 build)

## What's in this zip
This is the SIH26106 forensic platform being built on top of your
existing Link-Mirror-X repo. So far it can:
  - Parse a raw email (.eml file) into structured data
  - Detect sender-identity lies (fake display names, SPF/DKIM/DMARC fails,
    Reply-To mismatches)
  - Pull out URLs/domains/IPs/emails from an email automatically
  - Spot when multiple "different" phishing emails are secretly run from
    the same infrastructure (the campaign-correlation "wow" feature)

It does NOT yet include: the LinkMirror visual engine hookup, the
dashboard UI, or the report generator. Those come next.

## 1. Requirements
You need Python 3.9+ installed.

For the ingestion/correlation-only commands (stages 1-3), nothing else
is needed — pure Python standard library.

For the LinkMirror engine + full case pipeline (stages 4 onward), you
also need:
    pip install opencv-python numpy scikit-learn pillow torch torchvision python-whois tldextract

(torch/torchvision are the biggest download — a few hundred MB. If you
skip installing them, the engine still runs, but the visual-similarity
score will only reflect the ORB half, not the full ORB+ResNet fusion.)

Check your Python version:
    python3 --version    (or "py --version" on Windows)

## 2. Unzip and enter the folder
Unzip this file anywhere, then open a terminal inside it:
    cd linkmirror-forensics

## 3. Run each piece (no installation needed, pure Python)

Parse one of the demo emails:
    python3 -m ingestion.eml_parser demo_data/emails/case1_bank_verify.eml

Run the sender-forensics check on it:
    python3 -m ingestion.header_forensics demo_data/emails/case1_bank_verify.eml

Pull out the URLs/domains/IPs from it:
    python3 -m ingestion.indicator_extractor demo_data/emails/case1_bank_verify.eml

Run the correlation engine across ALL 5 demo emails at once (this is
the "find the hidden campaign" feature):
    python3 -m correlation.correlation_engine

Run the FULL pipeline on one email at once (parse -> header check ->
extract indicators -> find screenshot -> run LinkMirror engine),
all chained together automatically:
    python3 -m case.case_manager demo_data/emails/case1_bank_verify.eml

A demo reference image and a matching "captured" screenshot are
already included (reference_images/hdfc-real.png and
captured_screenshots/secure-verify.test.png) so this command works
out of the box without needing your own screenshots yet.

## 4. Run the actual dashboard (this is what a judge would see)
    pip install streamlit matplotlib networkx --break-system-packages

(drop --break-system-packages on Windows if pip complains about it —
that flag is only needed on some Linux setups)

    streamlit run app.py
    (or: py -m streamlit run app.py   if "streamlit" isn't recognized
     as a command on Windows)

This opens a browser tab. In the sidebar:
  - Click "Load all 5 demo emails" to process the whole demo set at once
  - Or upload your own .eml file and click "Process uploaded email"

Then explore the three tabs:
  - Overview: one row per case, color-coded by severity
  - Case details: pick one case, see every header finding, extracted
    indicator, and LinkMirror verdict
  - Threat graph / correlation: shows which cases secretly share
    infrastructure (the "hidden campaign" reveal)

That last command should print out that cases 1, 2, and 3 (pretending
to be HDFC Bank, PayPal, and Microsoft Office) all secretly share the
same server IP — even though they use three different fake brand names.
That's the core demo moment.

## 4. If you want to regenerate the demo emails
The 5 synthetic .eml files are already included in demo_data/emails/,
but if you ever want to regenerate or edit them:
    python3 demo_data/generate_demo_emails.py

## 5. Your next action item (separate from this zip)
In your ORIGINAL Link-Mirror-X repo (not this one), run these two
scripts to generate real + fake screenshots — I need their output to
wire up the visual-comparison piece next:
    cd Link-Mirror-X
    pip install selenium webdriver-manager
    python generate_reference_images.py
    python synthesize_phish_images.py --variants 3

That creates a `reference_images/` folder (real site screenshots) and
a `reference_synthetic/` folder (auto-generated fake phishing versions).
Once you have those, send them back (zip the two folders) and I'll wire
them into this project.

## Questions / errors
If any command above errors out, copy-paste the exact error back into
the chat and I'll fix it — don't worry about debugging it yourself.
