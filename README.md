# M3 Royal Wealth

A Flask-based portfolio investment analysis platform for Indian Mutual Fund Distributors (MFDs). Includes SIP, Lumpsum, Step-up SIP, Retirement, Goal-based SIP, SWP, XIRR, and Regret calculators, an AI Goal Planner, AI Wealth Assistant, client management, and PDF reports.

## Features

- **10+ Calculators** — SIP, Lumpsum, Step-up SIP, Goal-based SIP, Retirement, SWP, XIRR, Regret
- **AI Goal Planner** — Natural-language goal input, auto-routes to the right calculator and fills in params
- **AI Wealth Assistant** — Chat-based portfolio advice
- **XIRR vs CAGR vs Absolute** explainer — helps MFDs explain the right return metric to clients
- **Client management** — Store clients, portfolios, risk profiles
- **Meeting Mode** — Clean presentation UI for client meetings
- **PDF Reports** — Vector-drawn charts (jsPDF), downloadable from every calculator
- **Dark mode** across all pages
- **Currency toggle** — Indian (₹, lakh/crore) or Western ($, M/B)

## Tech Stack

- **Backend:** Flask 3, Werkzeug, Flask-WTF (CSRF), Flask-Limiter, Flask-Mail
- **Database:** SQLite (default) or Postgres via `DATABASE_URL`
- **Frontend:** Vanilla JS, Chart.js 4.4, jsPDF + jsPDF-autotable
- **AI:** Groq API (Llama 3 / Mixtral)
- **Deploy:** Render.com (one-click via `render.yaml`)

## Local Setup

```bash
# 1. Clone
git clone https://github.com/<your-username>/m3-royal-wealth.git
cd m3-royal-wealth

# 2. Virtual env
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate # macOS/Linux

# 3. Install deps
pip install -r requirements.txt

# 4. Environment variables (create .env or export manually)
set SECRET_KEY=your-random-secret-key
set GROQ_API_KEY=your-groq-key
set MAIL_USERNAME=you@gmail.com
set MAIL_PASSWORD=your-gmail-app-password
set FLASK_ENV=development

# 5. Run (DB auto-initializes on first startup — tables created via CREATE TABLE IF NOT EXISTS)
python app.py
# or: flask run
```

App runs on `http://localhost:5000`.

## Deploy to Render

1. Push this repo to GitHub.
2. On [render.com](https://render.com), click **New → Blueprint**.
3. Connect your GitHub repo — Render will detect `render.yaml` automatically.
4. After first deploy, fill in these env vars in the Render dashboard (they're marked `sync: false`):
   - `GROQ_API_KEY` — from [console.groq.com](https://console.groq.com)
   - `MAIL_USERNAME` — your Gmail address
   - `MAIL_PASSWORD` — [Gmail app password](https://myaccount.google.com/apppasswords) (NOT your regular password)
   - `DATABASE_URL` — optional, leave empty for SQLite or paste a Postgres URL
5. Click **Manual Deploy → Deploy latest commit** to pick up the new env vars.

> **Note:** The database auto-initializes on first startup (SQLite tables created via `CREATE TABLE IF NOT EXISTS`). You do **not** need to manually run `db_setup.py` on Render.

## Project Structure

```
m3_royal_wealth/
├── app.py                     # Main Flask app (routes, calculators, AI endpoints)
├── db_setup.py                # SQLite schema bootstrap
├── requirements.txt           # Python deps
├── Procfile                   # Heroku-style deploy config
├── render.yaml                # Render.com blueprint
├── .gitignore
├── README.md
├── static/
│   ├── calc-core.js           # Shared calculator formatting helpers
│   ├── design-tokens.css      # Theme tokens (gold, navy, cream)
│   ├── meeting-mode.css       # Presentation UI
│   ├── meeting-mode.js
│   └── style.css              # Global styles
└── templates/
    ├── base.html              # Layout + nav + theme toggle
    ├── dashboard.html         # Main dashboard with calculator tiles
    ├── xirr_calculator.html   # XIRR with vector PDF + CAGR comparison
    ├── ai_goal_planner.html   # Natural-language goal → calculator
    ├── ai_wealth_assistant.html
    ├── *_calculator.html      # SIP, Lumpsum, Step-up, Retirement, etc.
    ├── clients.html           # Client CRUD
    ├── portfolio.html         # Portfolio allocation viewer
    ├── reports.html           # PDF report generator
    ├── settings.html
    └── ... (auth: login, register, forgot, reset_password)
```

## Environment Variables

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `SECRET_KEY` | Yes | — | Flask session key. Generated automatically on Render. |
| `GROQ_API_KEY` | Yes (for AI) | — | AI Goal Planner + AI Wealth Assistant |
| `DATABASE_URL` | No | SQLite | Postgres URL for production |
| `MAIL_USERNAME` | For email | — | Gmail/SMTP user (forgot-password flow) |
| `MAIL_PASSWORD` | For email | — | Gmail **app password** |
| `MAIL_SERVER` | No | `smtp.gmail.com` | |
| `MAIL_PORT` | No | `587` | |
| `FLASK_ENV` | No | `development` | Set to `production` on Render |
| `FLASK_DEBUG` | No | `false` | Never `true` in production |

## Disclaimer

This is a portfolio analysis tool for educational and advisory use. All projections are indicative — past performance does not guarantee future results. Mutual fund investments are subject to market risks.

## License

Proprietary / all rights reserved. Contact repo owner for licensing.
