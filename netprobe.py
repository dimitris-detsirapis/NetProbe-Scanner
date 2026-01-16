import customtkinter as ctk
import nmap
import threading
import os
import sys
import subprocess
import requests
import time
from datetime import datetime
from tkinter import messagebox, filedialog
import webbrowser

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# --- RESOURCE PATH HELPER (For PyInstaller) ---
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# --- NMAP AUTO-INSTALLER ---
def check_nmap_installed():
    """Checks if nmap is in PATH."""
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (FileNotFoundError, Exception):
        return False

def install_nmap():
    """Extracts and runs the bundled Nmap installer."""
    installer_path = resource_path("nmap_installer.exe")
    
    if not os.path.exists(installer_path):
        messagebox.showerror("Error", "Nmap installer not found in bundle!\nPlease install Nmap manually.")
        return False

    answer = messagebox.askyesno(
        "Missing Dependency", 
        "Nmap is required but not installed.\n\nWould you like to install it now automatically?"
    )
    
    if answer:
        try:
            messagebox.showinfo("Installing", "The Nmap installer will now launch.\nPlease complete the installation (Accept All Defaults).")
            # /S is silent for Nmap, but Npcap (driver) will still pop up a window.
            subprocess.run([installer_path, "/S"], check=True)
            
            messagebox.showinfo("Success", "Nmap installed! Please restart NetProbe to detect the new path.")
            sys.exit() 
        except Exception as e:
            messagebox.showerror("Installation Failed", f"Error: {e}")
            sys.exit()
    else:
        messagebox.showwarning("Warning", "NetProbe cannot function without Nmap.")
        sys.exit()

class NetProbeApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("NetProbe v9.0 - Enterprise Edition")
        self.geometry("1100x850")

        # Layout Configuration
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # State Variables
        self.is_scanning = False
        self.stop_event = threading.Event()
        self.scan_start_time = None
        self.scan_results_data = [] 

        # 1. HEADER
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=20, pady=10, sticky="ew")
        
        self.label_title = ctk.CTkLabel(self.header_frame, text="🛡️ NetProbe Enterprise", font=("Roboto", 28, "bold"))
        self.label_title.pack(pady=5)
        self.label_subtitle = ctk.CTkLabel(self.header_frame, text="Auto-Dependency Management & Global Intelligence", font=("Roboto", 12), text_color="gray")
        self.label_subtitle.pack()

        # 2. INPUT
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.entry_target = ctk.CTkEntry(self.input_frame, placeholder_text="Target IP (e.g. 192.168.1.1) or Subnet (192.168.1.0/24)", width=350)
        self.entry_target.grid(row=0, column=0, padx=10, pady=20)

        self.scan_modes = {
            "Quick Scan (~15s)": "-F -T4",
            "Network Sweep (Ping /24) (~30s)": "-sn", 
            "Standard Port Scan (~2m)": "-p 1-1000 -T4",
            "Service & OS Detection (~3m)": "-sV -O -T4",
            "Vuln & Exploit Check (~5m+)": "-sV --script vuln" 
        }
        
        self.scan_option = ctk.CTkOptionMenu(self.input_frame, values=list(self.scan_modes.keys()), width=250)
        self.scan_option.grid(row=0, column=1, padx=10, pady=20)

        # BUTTONS
        self.btn_scan = ctk.CTkButton(self.input_frame, text="🚀 LAUNCH", command=self.start_scan_thread, fg_color="#c0392b", hover_color="#e74c3c", font=("Roboto", 14, "bold"))
        self.btn_scan.grid(row=0, column=2, padx=5, pady=20)

        self.btn_stop = ctk.CTkButton(self.input_frame, text="⏹️ ABORT", command=self.stop_scan, state="disabled", fg_color="#7f8c8d", width=80)
        self.btn_stop.grid(row=0, column=3, padx=5, pady=20)

        # 3. OUTPUT
        self.textbox_output = ctk.CTkTextbox(self, font=("Consolas", 13), text_color="#2ecc71", wrap="word")
        self.textbox_output.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")

        # 4. FOOTER
        self.footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.footer_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_clear = ctk.CTkButton(self.footer_frame, text="🧹 CLEAR", command=self.clear_console, fg_color="#444", hover_color="#555", width=80)
        self.btn_clear.pack(side="left", padx=10)

        self.btn_save = ctk.CTkButton(self.footer_frame, text="📄 Export HTML Report", command=self.save_html_report, fg_color="#2980b9")
        self.btn_save.pack(side="right", padx=10)

        self.log("System Ready. Auto-Installer Module Loaded.")

    def log(self, message):
        self.textbox_output.configure(state="normal")
        self.textbox_output.insert("end", message + "\n")
        self.textbox_output.configure(state="disabled")
        self.textbox_output.see("end")

    def clear_console(self):
        self.textbox_output.configure(state="normal")
        self.textbox_output.delete("0.0", "end")
        self.textbox_output.configure(state="disabled")
        self.log("Console cleared.")

    # --- INTELLIGENCE MODULES ---
    def check_cve(self, service_name, version):
        if not version or not service_name: return None
        try:
            url = f"https://cve.circl.lu/api/search/{service_name}"
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                data = response.json()
                found_cves = [entry['id'] for entry in data.get('results', [])[:3] if "summary" in entry]
                if found_cves: return f"⚠️ KNOWN CVEs: {', '.join(found_cves)}"
        except: pass
        return None

    def get_geoip_info(self, ip_address):
        if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("127."):
            return "Local Network (Private IP)"
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=3)
            data = response.json()
            if data['status'] == 'success':
                return f"{data.get('city')}, {data.get('country')} | ISP: {data.get('isp')}"
        except: pass
        return "GeoIP Lookup Failed"

    # --- SCANNING LOGIC ---
    def start_scan_thread(self):
        target = self.entry_target.get().strip()
        if not target: return

        self.is_scanning = True
        self.stop_event.clear()
        self.scan_start_time = time.time()
        self.scan_results_data = [] 
        
        self.btn_scan.configure(state="disabled")
        self.btn_stop.configure(state="normal", fg_color="#e74c3c")
        
        self.update_progress_heartbeat()
        
        selected_label = self.scan_option.get()
        nmap_args = self.scan_modes[selected_label]

        threading.Thread(target=self.run_nmap_scan, args=(target, selected_label, nmap_args)).start()

    def stop_scan(self):
        if self.is_scanning:
            self.stop_event.set()
            self.is_scanning = False
            self.log("\n🛑 OPERATION ABORTED BY USER.")
            self.reset_ui()

    def update_progress_heartbeat(self):
        if self.is_scanning and not self.stop_event.is_set():
            elapsed = int(time.time() - self.scan_start_time)
            minutes, seconds = divmod(elapsed, 60)
            time_str = f"{minutes}m {seconds:02d}s"

            if elapsed > 0 and elapsed % 10 == 0:
                self.log(f"⏳ Scanning... ({time_str} elapsed)")
            self.after(1000, self.update_progress_heartbeat)

    def reset_ui(self):
        self.btn_scan.configure(state="normal")
        self.btn_stop.configure(state="disabled", fg_color="#7f8c8d")
        self.is_scanning = False

    def run_nmap_scan(self, target, mode_label, arguments):
        self.log(f"\n{'='*50}")
        self.log(f"🚀 EXECUTING: {mode_label}")
        self.log(f"🎯 TARGET: {target}")
        self.log(f"{'='*50}\n")
        
        scanner = nmap.PortScanner()

        try:
            scanner.scan(target, arguments=arguments)
            
            if self.stop_event.is_set(): return

            for host in scanner.all_hosts():
                self.log(f"🔎 Analysing Host: {host}...")
                geo_location = self.get_geoip_info(host)

                host_data = {
                    "ip": host,
                    "status": scanner[host].state().upper(),
                    "hostname": scanner[host].hostname(),
                    "location": geo_location,
                    "ports": []
                }

                self.log(f"\n[+] Host: {host} ({host_data['status']})")
                self.log(f"    🌍 Location: {geo_location}")
                if host_data['hostname']: self.log(f"    Name: {host_data['hostname']}")

                if 'tcp' in scanner[host] or 'udp' in scanner[host]:
                    for proto in scanner[host].all_protocols():
                        ports = sorted(scanner[host][proto].keys())
                        for port in ports:
                            info = scanner[host][proto][port]
                            service = info['name']
                            version = info.get('version', '')
                            state = info['state']
                            
                            self.log(f"    • Port {port:<5} [{state.upper()}] : {service} {version}")
                            
                            port_entry = {
                                "port": port,
                                "protocol": proto.upper(),
                                "service": service,
                                "version": version,
                                "cve": ""
                            }

                            if version and "Vuln" not in mode_label and "Ping" not in mode_label:
                                cve = self.check_cve(service, version)
                                if cve: 
                                    self.log(f"      {cve}")
                                    port_entry["cve"] = cve

                            if 'script' in info:
                                for script_id, result in info['script'].items():
                                    self.log(f"      💀 {script_id}: {result.strip()}")
                                    port_entry["cve"] += f" | {script_id} found"

                            host_data["ports"].append(port_entry)

                self.scan_results_data.append(host_data)

            elapsed = int(time.time() - self.scan_start_time)
            minutes, seconds = divmod(elapsed, 60)
            self.log(f"\n✅ OPERATION COMPLETE: {minutes}m {seconds:02d}s")

        except Exception as e:
            self.log(f"❌ ERROR: {e}")
        finally:
            self.reset_ui()

    def save_html_report(self):
        if not self.scan_results_data:
            messagebox.showwarning("No Data", "Please run a complete scan first.")
            return

        filename = f"NetProbe_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NetProbe Scan Report</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background-color: #1e1e1e; color: #c0c0c0; margin: 20px; }}
                h1 {{ color: #ffffff; border-bottom: 2px solid #c0392b; padding-bottom: 10px; }}
                .summary {{ background: #252526; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .host-card {{ background: #2d2d30; margin-bottom: 15px; padding: 15px; border-left: 5px solid #2ecc71; box-shadow: 0 2px 5px rgba(0,0,0,0.3); }}
                .host-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #3e3e42; padding-bottom: 10px; margin-bottom: 10px; }}
                .ip {{ font-size: 1.2em; font-weight: bold; color: #ffffff; }}
                .location {{ font-size: 0.9em; color: #f1c40f; margin-right: 15px; }}
                .badge {{ background: #007acc; color: white; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th {{ text-align: left; background: #3e3e42; color: white; padding: 8px; }}
                td {{ border-bottom: 1px solid #3e3e42; padding: 8px; color: #d4d4d4; }}
                .vuln {{ color: #e74c3c; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>🛡️ NetProbe Global Audit</h1>
            <div class="summary">
                <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Hosts Found:</strong> {len(self.scan_results_data)}</p>
            </div>
        """

        for host in self.scan_results_data:
            html_content += f"""
            <div class="host-card">
                <div class="host-header">
                    <div>
                        <span class="ip">🖥️ {host['ip']}</span>
                    </div>
                    <div>
                        <span class="location">🌍 {host['location']}</span>
                        <span class="badge">{host['hostname'] if host['hostname'] else 'Unknown Host'}</span>
                    </div>
                </div>
            """
            
            if host['ports']:
                html_content += """
                <table>
                    <tr><th>Port</th><th>Service</th><th>Version</th><th>Risk/Info</th></tr>
                """
                for port in host['ports']:
                    risk_class = "vuln" if port['cve'] else ""
                    html_content += f"""
                    <tr>
                        <td>{port['port']}/{port['protocol']}</td>
                        <td>{port['service']}</td>
                        <td>{port['version']}</td>
                        <td class="{risk_class}">{port['cve']}</td>
                    </tr>
                    """
                html_content += "</table>"
            else:
                html_content += "<p><i>No open ports detected (Host is up).</i></p>"
            
            html_content += "</div>"

        html_content += "</body></html>"

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html_content)
            webbrowser.open('file://' + os.path.realpath(filename))
            self.log(f"\n[+] HTML Report Generated: {filename}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    if not check_nmap_installed():
        install_nmap()

    app = NetProbeApp()
    app.mainloop()