
# 🛡️ PhishNet: AI-Powered Email Security Sandbox

**PhishNet** is a secure, localized environment for analyzing suspicious emails. It combines **Google Gemini AI** with robust **heuristic analysis** to detect phishing attempts, while providing a sandboxed "Safe Preview" to view malicious content without risk.

![PhishNet Screenshot](https://via.placeholder.com/800x400?text=PhishNet+Dashboard+Preview)

## 🚀 Key Features

* **🧠 AI-First Detection Engine:** Uses **Google Gemini 2.5 Flash** (with auto-discovery) to analyze email context, intent, and coercion.
* **🛡️ Robust Fallback Heuristics (V7):** A "Unbreakable" backup layer that catches technical threats (Raw IPs, Punycode, Link Mismatches) even if AI fails.
* **🧪 Open Safely Mode:** Renders emails in a headless browser sandbox (Runner) to capture screenshots and extract links without exposing your local machine.
* **🔍 Deep Link Analysis:** Detects deceptive links (e.g., `paypal-support.com` vs `paypal.com`) using intelligent domain root matching.
* **🔐 Privacy Focused:** Self-hosted via Docker. Your emails stay on your machine (except for the text sent to Gemini API for analysis).



## 🏗️ Architecture

PhishNet runs as a multi-container Docker application:

```
graph TD
    User[User / Browser] -->|Uploads .eml| Web[Next.js Frontend]
    Web -->|API Calls| API[FastAPI Backend]
    API -->|Store Metadata| DB[(PostgreSQL)]
    API -->|Analyze Text| Gemini[Google Gemini API]
    API -->|Render & Screenshot| Runner[Headless Browser Service]
    Runner -->|Save Artifacts| Volume[Local Storage]

```

---

## 🛠️ Prerequisites

* **Docker Desktop** (Running and updated)
* **Google Gemini API Key** (Free tier is sufficient)
* [Get a free key here](https://aistudio.google.com/app/apikey)



---

## ⚡ Quick Start Guide

### 1. Clone the Repository

```bash
git clone [https://github.com/yourusername/phishnet.git](https://github.com/yourusername/phishnet.git)
cd phishnet

```

### 2. Configure Environment

Create a `.env` file in the root directory. You can copy the example below:

```ini
# .env file

# --- Database (Default) ---
POSTGRES_USER=phishnet
POSTGRES_PASSWORD=phishnet
POSTGRES_DB=phishnet

# --- AI Configuration ---
# Get Key: [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
GEMINI_API_KEY=AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# (Optional) OpenAI Support - Leave empty to use Gemini
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini

```

### 3. Launch with Docker

Run the following command to build and start the system.
*Note: The first run takes a few minutes to download the AI and Browser images.*

```powershell
docker compose up -d --build

```

### 4. Access the App

* **Frontend:** [http://localhost:3000](https://www.google.com/search?q=http://localhost:3000)
* **API Docs:** [http://localhost:8000/docs](https://www.google.com/search?q=http://localhost:8000/docs)

---

## 🖥️ Usage

1. **Upload:** Drag and drop an `.eml` file into the dashboard.
2. **Analysis:** The system runs two parallel checks:
* **AI:** Asks Gemini "Is this phishing?" (Contextual analysis).
* **Heuristics:** Checks for hard indicators (IP links, mismatched domains).


3. **Result:** You get a Score (0-100) and a Verdict (Safe, Suspicious, Phishing).
4. **Open Safely:** Click "Open Safely" to render the email in a remote browser and see what it looks like without clicking anything locally.

---

## 🔧 Troubleshooting

### "AI analysis unavailable; using heuristics"

* **Cause:** The container can't see your API key, or the key is invalid.
* **Fix:**
1. Check your `.env` file.
2. Run: `docker compose exec api env` to confirm the key is loaded.
3. If not, force recreate: `docker compose up -d --force-recreate api`



### "NetworkError" in Frontend

* **Cause:** The API container crashed or isn't ready.
* **Fix:** Check logs with `docker compose logs -f api`. If it's a syntax error, rebuild with `docker compose up -d --build api`.

### Gemini 404 / Model Not Found

* **Fix:** The system now has **Auto-Discovery**. It will automatically try `gemini-2.5-flash`, `1.5-flash`, and `1.5-pro` until it finds one your key supports. Just restart the API container to re-trigger discovery.

---

## 📂 Project Structure

* **`apps/api`**: Python FastAPI backend (Logic, DB, AI integration).
* **`apps/web`**: Next.js Frontend (UI, Uploads).
* **`apps/runner`**: Node.js/Puppeteer service for safe rendering.
* **`artifacts/`**: Stores screenshots and analyzed email data locally.

---

## 📜 License

MIT License. Use responsibly for educational and defensive security purposes.

```

```
