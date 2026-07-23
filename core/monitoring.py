"""
core/monitoring.py
==================
System monitoring and email alerting for Navigo.

Tracks:
- CPU / RAM / Disk usage
- API response times
- Model health
- Database connectivity
- Evasion rate spikes

Sends email alerts when thresholds are breached.
"""

import asyncio
import logging
import os
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, Optional

import psutil

logger = logging.getLogger("navigo.monitoring")

# ---------------------------------------------------------------------------
# Config from environment
# ---------------------------------------------------------------------------
from dotenv import load_dotenv
load_dotenv()

ALERT_FROM     = os.getenv("ALERT_EMAIL_FROM", "")
ALERT_TO       = os.getenv("ALERT_EMAIL_TO", "")
ALERT_PASSWORD = os.getenv("ALERT_EMAIL_PASSWORD", "")
SMTP_HOST      = os.getenv("ALERT_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT      = int(os.getenv("ALERT_SMTP_PORT", "587"))

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
CPU_THRESHOLD_PCT    = 90.0   # Alert if CPU > 90%
RAM_THRESHOLD_PCT    = 95.0   # Alert if RAM > 85%
DISK_THRESHOLD_PCT   = 95.0   # Alert if disk > 90%
LATENCY_THRESHOLD_MS = 5000   # Alert if avg latency > 5 seconds
EVASION_THRESHOLD    = 0.10   # Alert if evasion rate > 10%


# ---------------------------------------------------------------------------
# Email sender
# ---------------------------------------------------------------------------

def send_alert_email(subject: str, body: str) -> bool:
    """
    Send an HTML alert email via Gmail SMTP.
    Returns True if sent successfully, False otherwise.
    """
    if not ALERT_FROM or not ALERT_PASSWORD:
        logger.warning("Email alerts not configured — skipping.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[NAVIGO ALERT] {subject}"
        msg["From"]    = ALERT_FROM
        msg["To"]      = ALERT_TO

        # Plain text fallback
        text_part = MIMEText(body, "plain")

        # HTML version
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background: #0f172a; color: #f1f5f9; padding: 24px;">
            <div style="max-width: 600px; margin: 0 auto;">
                <div style="background: #1e293b; border-left: 4px solid #ef4444;
                            padding: 20px; border-radius: 8px;">
                    <h2 style="color: #ef4444; margin-top: 0;">
                        🛡️ Navigo Security Alert
                    </h2>
                    <h3 style="color: #f1f5f9;">{subject}</h3>
                    <pre style="background: #0f172a; padding: 16px; border-radius: 4px;
                                color: #94a3b8; font-size: 13px; white-space: pre-wrap;">
{body}
                    </pre>
                    <p style="color: #64748b; font-size: 12px; margin-bottom: 0;">
                        Navigo Adversarial Defense System &mdash;
                        {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        html_part = MIMEText(html_body, "html")

        msg.attach(text_part)
        msg.attach(html_part)

        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(ALERT_FROM, ALERT_PASSWORD)
            server.sendmail(ALERT_FROM, ALERT_TO, msg.as_string())

        logger.info("Alert email sent: %s", subject)
        return True

    except Exception as exc:
        logger.error("Failed to send alert email: %s", exc)
        return False


# ---------------------------------------------------------------------------
# System metrics collector
# ---------------------------------------------------------------------------

def collect_system_metrics() -> Dict[str, Any]:
    """Collect current system health metrics."""
    cpu    = psutil.cpu_percent(interval=1)
    ram    = psutil.virtual_memory()
    disk   = psutil.disk_usage("/")

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_percent": cpu,
        "ram_percent": ram.percent,
        "ram_used_gb": round(ram.used / 1e9, 2),
        "ram_total_gb": round(ram.total / 1e9, 2),
        "disk_percent": disk.percent,
        "disk_free_gb": round(disk.free / 1e9, 2),
    }


def check_thresholds(metrics: Dict[str, Any]) -> list:
    """Check metrics against thresholds. Returns list of alert messages."""
    alerts = []

    if metrics["cpu_percent"] > CPU_THRESHOLD_PCT:
        alerts.append(
            f"HIGH CPU: {metrics['cpu_percent']}% (threshold: {CPU_THRESHOLD_PCT}%)"
        )

    if metrics["ram_percent"] > RAM_THRESHOLD_PCT:
        alerts.append(
            f"HIGH RAM: {metrics['ram_percent']}% "
            f"({metrics['ram_used_gb']}GB / {metrics['ram_total_gb']}GB)"
        )

    if metrics["disk_percent"] > DISK_THRESHOLD_PCT:
        alerts.append(
            f"LOW DISK: {metrics['disk_percent']}% used "
            f"({metrics['disk_free_gb']}GB free)"
        )

    return alerts


# ---------------------------------------------------------------------------
# API-level alerting helpers (called from main.py)
# ---------------------------------------------------------------------------

def alert_high_evasion(evasion_rate: float) -> None:
    """Call this if evasion rate spikes above threshold."""
    if evasion_rate > EVASION_THRESHOLD:
        subject = f"Evasion Rate Spike: {evasion_rate:.2%}"
        body = (
            f"The adversarial evasion rate has exceeded the threshold.\n\n"
            f"Current evasion rate : {evasion_rate:.4f} ({evasion_rate:.2%})\n"
            f"Threshold            : {EVASION_THRESHOLD:.2%}\n\n"
            f"Immediate retraining is recommended.\n"
            f"Run: python training/train_model.py"
        )
        send_alert_email(subject, body)


def alert_db_down(error: str) -> None:
    """Call this if the database connection fails."""
    subject = "Database Connection Failed"
    body = (
        f"Navigo cannot connect to PostgreSQL.\n\n"
        f"Error: {error}\n\n"
        f"Check that PostgreSQL is running:\n"
        f"  Services -> postgresql-x64-18 -> Start"
    )
    send_alert_email(subject, body)


def alert_model_load_failed(error: str) -> None:
    """Call this if ML models fail to load."""
    subject = "ML Model Load Failed"
    body = (
        f"Navigo ML models failed to load at startup.\n\n"
        f"Error: {error}\n\n"
        f"Check that model files exist:\n"
        f"  models/lgb_model.pkl\n"
        f"  models/suspicion_model.pkl"
    )
    send_alert_email(subject, body)


# ---------------------------------------------------------------------------
# Background health monitor (runs every 5 minutes)
# ---------------------------------------------------------------------------

async def run_health_monitor(interval_seconds: int = 300):
    """
    Async background task — runs forever, checks system health every 5 minutes.
    Start this in FastAPI lifespan.
    """
    logger.info("Health monitor started (interval: %ds)", interval_seconds)

    while True:
        try:
            metrics = collect_system_metrics()
            alerts = check_thresholds(metrics)

            if alerts:
                subject = f"{len(alerts)} System Alert(s) Detected"
                body = (
                    f"System health check failed at "
                    f"{metrics['timestamp']}\n\n"
                    + "\n".join(f"• {a}" for a in alerts)
                    + f"\n\nFull metrics:\n"
                    + f"  CPU:  {metrics['cpu_percent']}%\n"
                    + f"  RAM:  {metrics['ram_percent']}% "
                    + f"({metrics['ram_used_gb']}GB / {metrics['ram_total_gb']}GB)\n"
                    + f"  Disk: {metrics['disk_percent']}% used "
                    + f"({metrics['disk_free_gb']}GB free)\n"
                )
                send_alert_email(subject, body)
                logger.warning("Health alerts: %s", alerts)
            else:
                logger.debug(
                    "Health OK — CPU: %s%% RAM: %s%% Disk: %s%%",
                    metrics["cpu_percent"],
                    metrics["ram_percent"],
                    metrics["disk_percent"],
                )

        except Exception as exc:
            logger.error("Health monitor error: %s", exc)

        await asyncio.sleep(interval_seconds)