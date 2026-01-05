# Windows Event Log Analyzer
# Detects suspicious events from Security.evtx or other event logs
# Author: Your Name
# Libraries: python-evtx, pandas, rich

from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import pandas as pd
from collections import defaultdict
from rich.console import Console
from rich.table import Table

console = Console()

# --- CONFIGURATION ---
EVENT_LOG_FILE = "Security.evtx"  # Path to your .evtx file
FAILED_LOGIN_EVENT_ID = 4625       # Failed login
ACCOUNT_CREATED_EVENT_ID = 4720    # New user account created
PRIV_ESCALATION_EVENT_ID = 4672    # Admin privileges granted
SERVICE_STOP_EVENT_ID = 7036       # Service stopped
FAILED_LOGIN_THRESHOLD = 5         # Example: Flag if >5 failed logins per user

# --- DATA STRUCTURES ---
failed_logins = defaultdict(int)
alerts = []

# --- HELPER FUNCTION: Parse XML from each event ---
def parse_event(record_xml):
    """
    Parses an event record from XML to a dictionary
    """
    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    root = ET.fromstring(record_xml)
    
    event_id = int(root.find("ns:System/ns:EventID", ns).text)
    time_created = root.find("ns:System/ns:TimeCreated", ns).attrib['SystemTime']
    
    # Get AccountName if exists
    account_name_elem = root.find(".//ns:Data[@Name='TargetUserName']", ns)
    account_name = account_name_elem.text if account_name_elem is not None else "N/A"
    
    # Message / description (optional)
    message_elem = root.find(".//ns:RenderingInfo/ns:Message", {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"})
    message = message_elem.text if message_elem is not None else ""
    
    return {
        "EventID": event_id,
        "Time": time_created,
        "Account": account_name,
        "Message": message
    }

# --- MAIN FUNCTION: Analyze Events ---
def analyze_events(evtx_file):
    with Evtx(evtx_file) as log:
        for record in log.records():
            event = parse_event(record.xml())
            
            # Check for failed login
            if event["EventID"] == FAILED_LOGIN_EVENT_ID:
                failed_logins[event["Account"]] += 1
                if failed_logins[event["Account"]] >= FAILED_LOGIN_THRESHOLD:
                    alerts.append({
                        "Time": event["Time"],
                        "Account": event["Account"],
                        "Type": "Multiple Failed Logins",
                        "Details": f"{failed_logins[event['Account']]} failed attempts"
                    })
            
            # Check for new account creation
            elif event["EventID"] == ACCOUNT_CREATED_EVENT_ID:
                alerts.append({
                    "Time": event["Time"],
                    "Account": event["Account"],
                    "Type": "New User Account Created",
                    "Details": event["Message"]
                })
            
            # Check for privilege escalation
            elif event["EventID"] == PRIV_ESCALATION_EVENT_ID:
                alerts.append({
                    "Time": event["Time"],
                    "Account": event["Account"],
                    "Type": "Privilege Escalation",
                    "Details": event["Message"]
                })
            
            # Check for service stop
            elif event["EventID"] == SERVICE_STOP_EVENT_ID:
                alerts.append({
                    "Time": event["Time"],
                    "Account": event["Account"],
                    "Type": "Service Stopped",
                    "Details": event["Message"]
                })

# --- FUNCTION: Display Alerts in Console ---
def display_alerts():
    if not alerts:
        console.print("[green]No suspicious events detected![/green]")
        return
    
    table = Table(title="Suspicious Windows Events Detected")
    table.add_column("Time", style="cyan")
    table.add_column("Account", style="magenta")
    table.add_column("Type", style="red")
    table.add_column("Details", style="yellow")
    
    for alert in alerts:
        table.add_row(alert["Time"], alert["Account"], alert["Type"], alert["Details"])
    
    console.print(table)

# --- FUNCTION: Save Alerts to CSV ---
def save_alerts_csv(filename="alerts_report.csv"):
    if alerts:
        df = pd.DataFrame(alerts)
        df.to_csv(filename, index=False)
        console.print(f"[blue]Alerts saved to {filename}[/blue]")

# --- RUN ANALYZER ---
if __name__ == "__main__":
    console.print("[bold green]Starting Windows Event Log Analyzer...[/bold green]")
    analyze_events(EVENT_LOG_FILE)
    display_alerts()
    save_alerts_csv()
    console.print("[bold green]Analysis Complete![/bold green]")
