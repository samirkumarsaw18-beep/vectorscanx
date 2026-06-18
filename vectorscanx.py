import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import os
import shutil
import json
import sys
import time
import datetime
from pathlib import Path

# --- HASHING UTILITY ---
def get_file_hash(file_path):
    """Calculates the SHA256 hash of a file."""
    h = hashlib.sha256()
    try:
        # Use a larger buffer for potentially faster hashing
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, PermissionError, Exception):
        return None

# --- DATABASE AND FILE SETUP ---
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

DATABASE_FILE = os.path.join(application_path, "malware_hashes.json")
QUARANTINE_FOLDER = os.path.join(application_path, "quarantine")

# --- INITIAL SETUP FUNCTION ---
def setup_initial_database():
    """Calculates hashes for new threat files and updates the database."""
    # Hardcoded list of new threat files and their respective original content
    new_threat_files = {
        "secret_agent.txt": "mission",
        "danger_script.txt": "powershell",
    }
    
    # 1. Calculate hashes for the new content
    new_hashes = {}
    for filename, content in new_threat_files.items():
        # Write the content to a temporary file or calculate hash directly from content
        h = hashlib.sha256(content.encode('utf-8')).hexdigest()
        new_hashes[filename] = h

    # 2. Load existing hashes from the database file
    existing_data = {}
    try:
        with open(DATABASE_FILE, "r") as f:
            existing_data = json.load(f)
            if not isinstance(existing_data, dict):
                 existing_data = {"description": "VectorScanX Database", "hashes": []}
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = {"description": "VectorScanX Database", "hashes": []}

    # 3. Add unique new hashes to the database set
    database_set = set(existing_data.get("hashes", []))
    newly_added_count = 0

    for h in new_hashes.values():
        if h not in database_set:
            database_set.add(h)
            newly_added_count += 1
    
    # 4. Save the updated database back to the file
    updated_data = {
        "description": existing_data.get("description", "VectorScanX Database"),
        "hashes": sorted(list(database_set))
    }

    try:
        with open(DATABASE_FILE, "w") as f:
            json.dump(updated_data, f, indent=2)
        print(f"Database setup complete. Added {newly_added_count} new signatures.")
    except Exception as e:
        print(f"Error saving updated database: {e}")

    # Return the final set of hashes for the app to use
    return database_set

# --- MAIN APPLICATION CLASS ---
class VectorScanXApp:
    def __init__(self, root):
        self.root = root
        self.root.geometry("1024x700")
        self.root.minsize(900, 600)
        # NEW: Darker, futuristic background color
        self.root.configure(bg="#0a0a0a")

        # State variables
        self.total_files_var = tk.IntVar(value=0)
        self.scanned_files_var = tk.IntVar(value=0)
        self.threats_found_var = tk.IntVar(value=0)
        self.last_scan_var = tk.StringVar(value="Waiting for command...")
        self.current_mode_var = tk.StringVar(value="STANDBY")
        self.is_scanning = False # Flag for animation

        # Initial database setup is run here
        self.malware_hashes = setup_initial_database()

        # --- Style / Theme Initialization ---
        self.setup_styles()

        self.root.title(f"VectorScanX : A modern heuristic threat scanner // DB: {len(self.malware_hashes)}")
        self.create_widgets()

    # ========== NEW FUTURISTIC STYLES ==========
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # --- NEW COLOR PALETTE ---
        bg_main = "#0a0a0a"      # Near black background
        bg_card = "#121212"      # slightly lighter card background
        bg_darker = "#050505"    # Very dark headers
        accent_neon = "#00ffd5"  # Bright Neon Cyan
        text_bright = "#ffffff"  # Pure white text
        text_muted = "#667788"   # Muted blue-gray tech text
        danger_red = "#ff3838"   # Bright neon red
        warning_orange = "#ffb302" # Bright neon orange

        # --- Fonts ---
        font_header = ("Consolas", 22, "bold")
        font_sub = ("Segoe UI", 10)
        font_bold = ("Segoe UI", 10, "bold")
        font_tech = ("Consolas", 10)

        # --- Frame & Label Configuration ---
        style.configure("TFrame", background=bg_main)
        style.configure("Card.TFrame", background=bg_card, relief="flat", borderwidth=1, bordercolor=accent_neon)
        
        style.configure("TLabel", background=bg_main, foreground=text_bright, font=font_sub)
        style.configure("Card.TLabel", background=bg_card, foreground=text_bright, font=font_sub)
        style.configure("Muted.TLabel", background=bg_card, foreground=text_muted, font=font_tech)
        
        style.configure("Title.TLabel", font=font_header, foreground=accent_neon, background=bg_main)
        style.configure("Subtitle.TLabel", font=font_sub, foreground=text_muted, background=bg_main)

        # --- NEW Animated Pulse Label Style ---
        style.configure("Pulse.TLabel", font=("Consolas", 12, "bold"), foreground=accent_neon, background=bg_main)

        # --- NEW Button Configuration ---
        style.configure("TButton", font=font_bold, borderwidth=0, padding=8, relief="flat", background=bg_card, foreground=accent_neon)
        style.map("TButton",
                  background=[("active", accent_neon), ("pressed", accent_neon)],
                  foreground=[("active", bg_main), ("pressed", bg_main)])

        style.configure("Primary.TButton", background=accent_neon, foreground=bg_main, font=("Segoe UI", 11, "bold"))
        style.map("Primary.TButton",
                  background=[("active", "#ffffff")], 
                  foreground=[("active", bg_main)])

        style.configure("Danger.TButton", foreground=danger_red, background=bg_card)
        style.map("Danger.TButton", background=[("active", danger_red)], foreground=[("active", text_bright)])

        style.configure("Warning.TButton", foreground=warning_orange, background=bg_card)
        style.map("Warning.TButton", background=[("active", warning_orange)], foreground=[("active", bg_main)])

        # --- Treeview (Results Table) Configuration ---
        style.configure(
            "Treeview",
            background=bg_card,
            foreground=text_bright,
            fieldbackground=bg_card,
            rowheight=32,
            font=font_tech,
            borderwidth=0,
            padding=10
        )
        style.map("Treeview", background=[("selected", "#1e3a57")], foreground=[("selected", accent_neon)])
        
        style.configure(
            "Treeview.Heading",
            font=("Consolas", 11, "bold"),
            background=bg_darker,
            foreground=accent_neon,
            relief="flat",
            padding=8
        )

        # --- Progress Bar ---
        style.configure("TProgressbar", background=accent_neon, troughcolor=bg_card, borderwidth=0, thickness=4)


    # ========== UI LAYOUT ==========
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- HEADER AREA ---
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))

        # Left Side: Title and Subtitle
        header_left = ttk.Frame(header_frame)
        header_left.pack(side=tk.LEFT)

        title_label = ttk.Label(header_left, text="[ VectorScanX ]", style="Title.TLabel")
        title_label.pack(anchor="w")

        subtitle = ttk.Label(header_left, text="Advanced heuristic & signature threat detection system.", style="Subtitle.TLabel")
        subtitle.pack(anchor="w")

        # Right Side: NEW Animation Indicator
        header_right = ttk.Frame(header_frame)
        header_right.pack(side=tk.RIGHT, anchor="center")

        self.pulse_label = ttk.Label(header_right, text="● SYSTEM IDLE", style="Pulse.TLabel")
        self.pulse_label.pack(pady=10)

        # --- DASHBOARD AREA (Controls + Stats) ---
        dash_wrapper = ttk.Frame(main_frame)
        dash_wrapper.pack(fill=tk.X, pady=(5, 15))

        # Left Area: Controls Buttons
        controls_frame = ttk.Frame(dash_wrapper)
        controls_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        ttk.Label(controls_frame, text="INITIATE SCAN OPERATIONS:", style="Subtitle.TLabel", font=("Consolas", 10)).pack(anchor="w", pady=(0,5))

        btn_quick = ttk.Button(controls_frame, text=">> QUICK SCAN (HOME)", command=self.quick_scan, style="Primary.TButton", cursor="hand2", width=22)
        btn_quick.pack(pady=(0, 8), anchor="w")

        btn_custom = ttk.Button(controls_frame, text=">> CUSTOM FOLDER SCAN", command=self.scan_folder, style="TButton", cursor="hand2", width=22)
        btn_custom.pack(pady=(0, 8), anchor="w")

        btn_update = ttk.Button(controls_frame, text=">> UPDATE DATABASE", command=self.update_database, style="TButton", cursor="hand2", width=22)
        btn_update.pack(anchor="w")

        # Center Area: Progress
        progress_frame = ttk.Frame(dash_wrapper, padding=(20, 0))
        progress_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, anchor="s")
        
        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate", style="TProgressbar")
        # Progress bar is hidden until needed
        
        # Right Area: Stats Card
        stats_card = ttk.Frame(dash_wrapper, style="Card.TFrame", padding=12)
        stats_card.pack(side=tk.RIGHT)

        ttk.Label(stats_card, text="[ SYSTEM STATUS ]", style="Card.TLabel", font=("Consolas", 11, "bold"), foreground="#00ffd5").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        ttk.Label(stats_card, text="OPERATIONAL MODE:", style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Label(stats_card, textvariable=self.current_mode_var, style="Card.TLabel", font=("Consolas", 10)).grid(row=1, column=1, sticky="w", padx=10)

        ttk.Label(stats_card, text="FILES PROCESSED:", style="Muted.TLabel").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Label(stats_card, textvariable=self.scanned_files_var, style="Card.TLabel", font=("Consolas", 10)).grid(row=2, column=1, sticky="w", padx=10)

        ttk.Label(stats_card, text="THREATS DETECTED:", style="Muted.TLabel").grid(row=3, column=0, sticky="w", pady=2)
        self.threat_label = ttk.Label(stats_card, textvariable=self.threats_found_var, style="Card.TLabel", font=("Consolas", 10, "bold"))
        self.threat_label.grid(row=3, column=1, sticky="w", padx=10)

        ttk.Label(stats_card, text="LAST OPERATION:", style="Muted.TLabel").grid(row=4, column=0, sticky="w", pady=(8, 2))
        ttk.Label(stats_card, textvariable=self.last_scan_var, style="Muted.TLabel", wraplength=200).grid(row=4, column=1, sticky="w", padx=10, pady=(8,0))


        # --- RESULTS TABLE AREA ---
        results_frame = ttk.Frame(main_frame, style="Card.TFrame", padding=2)
        results_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("type", "path", "reason")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", selectmode="browse", style="Treeview")
        self.results_tree.heading("type", text="[ THREAT TYPE ]")
        self.results_tree.heading("path", text="[ FILE PATH ]")
        self.results_tree.heading("reason", text="[ DETECTION DETAILS ]")

        self.results_tree.column("type", width=160, anchor="center", minwidth=140)
        self.results_tree.column("path", width=450, anchor="w", minwidth=350)
        self.results_tree.column("reason", width=350, anchor="w", minwidth=250)

        self.results_tree.tag_configure("signature", foreground="#ff3838")   # Neon Red
        self.results_tree.tag_configure("heuristic", foreground="#ffb302")   # Neon Orange

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.results_tree.bind("<Double-1>", self.open_file_location)

        # --- BOTTOM ACTIONS FOOTER ---
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X, pady=(15, 0))

        actions_frame = ttk.Frame(bottom_frame)
        actions_frame.pack(side=tk.LEFT)

        ttk.Button(actions_frame, text="[ QUARANTINE SELECTED ]", command=self.quarantine_selected, style="Warning.TButton", cursor="hand2").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(actions_frame, text="[ DELETE SELECTED ]", command=self.delete_selected, style="Danger.TButton", cursor="hand2").pack(side=tk.LEFT)

        # Status label
        self.status_label = ttk.Label(bottom_frame, text="System ready. Awaiting input.", style="Muted.TLabel", anchor="e")
        self.status_label.pack(side=tk.RIGHT, pady=5)

    # ========== NEW ANIMATION LOGIC ==========
    def animate_pulse(self, bright=True):
        """Handles the pulsing animation of the 'SCAN ACTIVE' label."""
        if not self.is_scanning:
            # Reset when scanning stops
            self.pulse_label.config(text="● SYSTEM IDLE", foreground="#00ffd5")
            return

        if bright:
            # Bright neon phase
            self.pulse_label.config(foreground="#00ffd5", text=">>> SCAN ACTIVE <<<")
            next_call = lambda: self.animate_pulse(bright=False)
        else:
            # Dim/dark phase
            self.pulse_label.config(foreground="#0a0a0a", text=">>> SCAN ACTIVE <<<")
            next_call = lambda: self.animate_pulse(bright=True)
        
        # Schedule next frame in 600ms
        self.root.after(600, next_call)


    # ========== CORE FUNCTIONS (Modified for integrated database) ==========
    def load_malware_hashes(self):
        """Loads the current set of malware hashes from the instance variable."""
        return self.malware_hashes

    def update_database(self):
        """Allows user to select a new database file to load and update."""
        filepath = filedialog.askopenfilename(title="Select new malware database json", filetypes=[("JSON files", "*.json")])
        if filepath:
            try:
                # 1. Load the new hashes from the selected file
                with open(filepath, "r") as f:
                    new_data = json.load(f)
                    new_hashes_set = set(new_data.get("hashes", []))
                
                # 2. Merge with existing hashes
                current_count = len(self.malware_hashes)
                self.malware_hashes.update(new_hashes_set)
                
                newly_added_count = len(self.malware_hashes) - current_count

                # 3. Save the merged set back to the official database file (DATABASE_FILE)
                updated_data = {
                    "description": "VectorScanX Database (User Updated)",
                    "hashes": sorted(list(self.malware_hashes))
                }
                with open(DATABASE_FILE, "w") as f:
                    json.dump(updated_data, f, indent=2)

                self.root.title(f"VectorScanX : A modern heuristic threat scanner // DB: {len(self.malware_hashes)}")
                messagebox.showinfo("Success", f"Database updated.\n{len(self.malware_hashes)} total signatures loaded.\n({newly_added_count} new signatures added from file.)")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update database: {e}")

    def quick_scan(self):
        """Initiates a scan of the user's home directory."""
        home_dir = os.path.expanduser("~")
        if messagebox.askyesno("Confirm Quick Scan", f"Initiate scan of home directory?\n\n{home_dir}"):
            self.run_scan(home_dir, mode_name="QUICK SCAN (HOME)")

    def scan_folder(self):
        """Prompts user for a folder and initiates a scan."""
        folder_path = filedialog.askdirectory(title="Select Target Sector")
        if folder_path:
            self.run_scan(folder_path, mode_name="CUSTOM FOLDER SCAN")

    # --- MAIN SCAN LOGIC ---
    def run_scan(self, folder_path, mode_name="Scan"):
        """Performs the recursive file scan and threat checks."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        self.current_mode_var.set(mode_name)
        self.scanned_files_var.set(0)
        self.threats_found_var.set(0)
        self.threat_label.config(foreground="#ffffff") # Reset threat color
        self.status_label.config(text=f"Initializing scan sequence: {folder_path}...")
        self.root.update_idletasks()

        # Start Animation and Progress
        self.is_scanning = True
        self.animate_pulse(True) 
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, anchor="s", pady=(10,0))
        self.progress.start(10)

        found_threats = 0
        scanned = 0
        start_time = time.time()

        for foldername, _, filenames in os.walk(folder_path):
            for filename in filenames:
                # Safety check to keep UI responsive
                if scanned % 50 == 0:
                     self.root.update()

                full_path = os.path.join(foldername, filename)
                scanned += 1
                self.scanned_files_var.set(scanned)

                try:
                    # Hash check (Signature Detection)
                    file_hash = get_file_hash(full_path)
                    if file_hash and file_hash in self.malware_hashes:
                        self.log_threat(full_path, "SIGNATURE MATCH", "Known malware hash detected", "signature")
                        found_threats += 1
                    else:
                        # Heuristic check
                        heuristic_threats = self.heuristic_analysis(full_path)
                        if heuristic_threats:
                            details = " / ".join(heuristic_threats)
                            self.log_threat(full_path, "HEURISTIC ANOMALY", details, "heuristic")
                            found_threats += 1
                except Exception:
                    pass # Ignore file access errors during scan

                if scanned % 25 == 0:
                    self.status_label.config(text=f"Scanning sector... {scanned} files analyzed.")

        # Stop Animation and Progress
        self.is_scanning = False
        self.progress.stop()
        self.progress.pack_forget()

        elapsed = time.time() - start_time
        self.threats_found_var.set(found_threats)
        
        # Update threat color if threats found
        if found_threats > 0:
             self.threat_label.config(foreground="#ff3838")

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.last_scan_var.set(f"FINISHED AT {timestamp} // {mode_name}")
        self.status_label.config(text=f"Operation complete. {scanned} files in {elapsed:.1f}s. {found_threats} threats detected.")
        self.current_mode_var.set("STANDBY")

    def log_threat(self, file_path, threat_type, details, tag):
        """Adds a threat entry to the results treeview."""
        self.results_tree.insert("", "end", values=(threat_type, file_path, details), tags=(tag,))
        self.results_tree.yview_moveto(1)

    # ========== HEURISTIC ANALYSIS (Unchanged logic) ==========
    def heuristic_analysis(self, full_path):
        threats_found = []
        filename = os.path.basename(full_path)
        
        # 1. Double Extension Check
        parts = filename.lower().split('.')
        if len(parts) > 2 and \
           parts[-1] in ['exe', 'bat', 'cmd', 'ps1', 'vbs', 'scr'] and \
           parts[-2] in ['pdf', 'jpg', 'png', 'gif', 'txt', 'doc', 'docx', 'xls', 'xlsx']:
            threats_found.append("High-risk double extension disguised file")
        
        # 2. Suspicious File Locations (simple example)
        suspicious_dirs = [
            os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"),
            os.path.join(os.path.expanduser("~"), "AppData", "Roaming"),
            os.path.join(os.path.expanduser("~"), "Downloads"),
            os.path.join(os.path.expanduser("~"), "Public"),
            "C:\\Windows\\Temp",
            "C:\\ProgramData"
        ]
        
        file_dir = os.path.dirname(full_path)
        if any(susp_dir.lower() in file_dir.lower() for susp_dir in suspicious_dirs):
            base_name_no_ext = os.path.splitext(filename)[0]
            if len(base_name_no_ext) > 7 and len(base_name_no_ext) < 33 and base_name_no_ext.isalnum():
                if filename.endswith(('.exe', '.dll', '.vbs', '.js', '.ps1')):
                    threats_found.append(f"Suspicious file name/location: '{filename}' in '{file_dir}'")
        
        # 3. Basic content check for suspicious strings
        try:
            if os.path.getsize(full_path) < 5 * 1024 * 1024:
                with open(full_path, 'r', errors='ignore') as f:
                    content = f.read(4096).lower()
                    suspicious_keywords = [
                        'powershell -enc', 'borland delphi', 'upx!', 'mimikatz',
                        'rundll32', 'create remote thread', 'setwindowshookex',
                        'reg add hklm', 'reg add hkcu', 'runonce', 'autorun',
                        'shellcode', 'base64_decode', 'eval(', 'document.write(',
                        'wshell.run', 'activexobject', 'adodb.stream',
                        'mshta.exe', 'certutil -decode',
                        'vba macro', 'enable content'
                    ]
                    for kw in suspicious_keywords:
                        if kw in content:
                            threats_found.append(f"Suspicious string identifier: '{kw}'")
        except Exception as e:
            pass
        
        return threats_found

    # ========== ACTIONS (Unchanged logic) ==========
    def get_selected_file_path(self):
        """Retrieves the file path of the selected item in the treeview."""
        try:
            selected_item = self.results_tree.selection()[0]
            return self.results_tree.item(selected_item, "values")[1]
        except IndexError:
            messagebox.showwarning("Input Required", "Select a threat target from the list first.")
            return None

    def quarantine_selected(self):
        """Moves the selected threat file to the quarantine folder."""
        file_path = self.get_selected_file_path()
        if not file_path: return
        if not os.path.exists(QUARANTINE_FOLDER): os.makedirs(QUARANTINE_FOLDER)
        try:
            dest = os.path.join(QUARANTINE_FOLDER, os.path.basename(file_path) + "_" + str(int(time.time())) + ".qrtn")
            shutil.move(file_path, dest)
            messagebox.showinfo("Containment Success", f"Target quarantined successfully.")
            self.results_tree.delete(self.results_tree.selection()[0])
        except Exception as e:
            messagebox.showerror("Containment Failure", f"Could not quarantine file:\n{e}")

    def delete_selected(self):
        """Permanently deletes the selected threat file."""
        file_path = self.get_selected_file_path()
        if not file_path: return
        if messagebox.askyesno("Confirm Eradication", "Permantently delete this target from the system? This cannot be undone."):
            try:
                os.remove(file_path)
                messagebox.showinfo("Eradication Success", "Target eliminated from filesystem.")
                self.results_tree.delete(self.results_tree.selection()[0])
            except Exception as e:
                messagebox.showerror("Eradication Failure", f"Could not delete file:\n{e}")

    def open_file_location(self, event=None):
        """Opens the folder containing the selected file."""
        item_id = self.results_tree.identify_row(event.y)
        if not item_id: return
        file_path = self.results_tree.item(item_id, "values")[1]
        folder = os.path.dirname(file_path)
        try:
            if sys.platform.startswith("win"): os.startfile(folder)
            elif sys.platform == "darwin": os.system(f'open "{folder}"')
            else: os.system(f'xdg-open "{folder}"')
        except: pass

if __name__ == "__main__":
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
        
    root = tk.Tk()
    app = VectorScanXApp(root)
    root.mainloop()