#!/usr/bin/env python3
"""
Advanced File Integrity Monitoring (FIM) Tool
A comprehensive cybersecurity tool for monitoring and maintaining file integrity
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import hashlib
import os
import json
import threading
import time
from datetime import datetime
from pathlib import Path
import queue

class FileIntegrityMonitor:
    def __init__(self):
        self.baseline_file = "fim_baseline.json"
        self.baseline = {}
        self.monitoring = False
        self.monitor_thread = None
        self.alert_queue = queue.Queue()
        
    def calculate_hash(self, filepath, algorithm='sha256'):
        """Calculate hash of a file using specified algorithm"""
        try:
            hash_func = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            return None
    
    def get_file_metadata(self, filepath):
        """Get file metadata including size, modification time, and permissions"""
        try:
            stat = os.stat(filepath)
            return {
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'permissions': oct(stat.st_mode)[-3:]
            }
        except Exception as e:
            return None
    
    def create_baseline(self, directory, hash_algorithm='sha256'):
        """Create baseline of all files in directory"""
        baseline = {}
        file_count = 0
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    file_hash = self.calculate_hash(filepath, hash_algorithm)
                    metadata = self.get_file_metadata(filepath)
                    
                    if file_hash and metadata:
                        baseline[filepath] = {
                            'hash': file_hash,
                            'algorithm': hash_algorithm,
                            'metadata': metadata,
                            'timestamp': time.time()
                        }
                        file_count += 1
                except Exception as e:
                    continue
        
        return baseline, file_count
    
    def save_baseline(self, baseline):
        """Save baseline to file"""
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2)
            return True
        except Exception as e:
            return False
    
    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(self.baseline_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            return {}
    
    def verify_integrity(self, directory):
        """Verify file integrity against baseline"""
        if not self.baseline:
            return {'error': 'No baseline loaded'}
        
        results = {
            'modified': [],
            'deleted': [],
            'new': [],
            'errors': []
        }
        
        # Check for modifications and deletions
        for filepath, baseline_data in self.baseline.items():
            if not os.path.exists(filepath):
                results['deleted'].append({
                    'path': filepath,
                    'baseline_hash': baseline_data['hash']
                })
                continue
            
            try:
                current_hash = self.calculate_hash(filepath, baseline_data['algorithm'])
                current_metadata = self.get_file_metadata(filepath)
                
                if current_hash != baseline_data['hash']:
                    results['modified'].append({
                        'path': filepath,
                        'baseline_hash': baseline_data['hash'],
                        'current_hash': current_hash,
                        'metadata_changed': current_metadata != baseline_data['metadata']
                    })
            except Exception as e:
                results['errors'].append({
                    'path': filepath,
                    'error': str(e)
                })
        
        # Check for new files
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                if filepath not in self.baseline:
                    try:
                        current_hash = self.calculate_hash(filepath)
                        results['new'].append({
                            'path': filepath,
                            'hash': current_hash
                        })
                    except Exception as e:
                        continue
        
        return results
    
    def continuous_monitor(self, directory, interval, callback):
        """Continuously monitor directory for changes"""
        while self.monitoring:
            results = self.verify_integrity(directory)
            # Always send results, even if no changes (for status update)
            callback(results)
            time.sleep(interval)


class FIMApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced File Integrity Monitor (FIM)")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2b2b2b')
        
        self.fim = FileIntegrityMonitor()
        self.monitored_directory = None
        self.monitoring_active = False
        
        self.setup_ui()
        self.check_alert_queue()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Header
        header = tk.Frame(self.root, bg='#1e1e1e', height=60)
        header.pack(fill='x', padx=0, pady=0)
        
        title_label = tk.Label(header, text="🛡️ File Integrity Monitor", 
                              font=('Helvetica', 18, 'bold'),
                              bg='#1e1e1e', fg='#00ff00')
        title_label.pack(pady=15)
        
        # Main container
        main_container = tk.Frame(self.root, bg='#2b2b2b')
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left panel - Controls
        left_panel = tk.Frame(main_container, bg='#3a3a3a', width=300)
        left_panel.pack(side='left', fill='y', padx=(0, 5))
        left_panel.pack_propagate(False)
        
        # Directory Selection
        dir_frame = tk.LabelFrame(left_panel, text="Target Directory", 
                                 bg='#3a3a3a', fg='white', font=('Helvetica', 10, 'bold'))
        dir_frame.pack(fill='x', padx=10, pady=10)
        
        self.dir_label = tk.Label(dir_frame, text="No directory selected", 
                                 bg='#3a3a3a', fg='#cccccc', wraplength=260)
        self.dir_label.pack(pady=5)
        
        tk.Button(dir_frame, text="Select Directory", command=self.select_directory,
                 bg='#4a4a4a', fg='white', relief='flat').pack(pady=5)
        
        # Baseline Controls
        baseline_frame = tk.LabelFrame(left_panel, text="Baseline Management", 
                                      bg='#3a3a3a', fg='white', font=('Helvetica', 10, 'bold'))
        baseline_frame.pack(fill='x', padx=10, pady=10)
        
        # Hash Algorithm Selection
        algo_frame = tk.Frame(baseline_frame, bg='#3a3a3a')
        algo_frame.pack(fill='x', pady=5)
        
        tk.Label(algo_frame, text="Hash Algorithm:", bg='#3a3a3a', fg='white').pack(side='left', padx=5)
        
        self.hash_var = tk.StringVar(value='sha256')
        hash_menu = ttk.Combobox(algo_frame, textvariable=self.hash_var, 
                                values=['md5', 'sha1', 'sha256', 'sha512'],
                                state='readonly', width=10)
        hash_menu.pack(side='left', padx=5)
        
        tk.Button(baseline_frame, text="Create Baseline", command=self.create_baseline,
                 bg='#0066cc', fg='white', relief='flat').pack(fill='x', padx=5, pady=2)
        
        tk.Button(baseline_frame, text="Load Baseline", command=self.load_baseline,
                 bg='#4a4a4a', fg='white', relief='flat').pack(fill='x', padx=5, pady=2)
        
        tk.Button(baseline_frame, text="Verify Integrity", command=self.verify_integrity,
                 bg='#00aa00', fg='white', relief='flat').pack(fill='x', padx=5, pady=2)
        
        # Monitoring Controls
        monitor_frame = tk.LabelFrame(left_panel, text="Continuous Monitoring", 
                                     bg='#3a3a3a', fg='white', font=('Helvetica', 10, 'bold'))
        monitor_frame.pack(fill='x', padx=10, pady=10)
        
        interval_frame = tk.Frame(monitor_frame, bg='#3a3a3a')
        interval_frame.pack(fill='x', pady=5)
        
        tk.Label(interval_frame, text="Interval:", bg='#3a3a3a', fg='white').pack(side='left', padx=5)
        
        self.interval_var = tk.StringVar(value='10')
        interval_entry = tk.Entry(interval_frame, textvariable=self.interval_var, width=8)
        interval_entry.pack(side='left', padx=2)
        
        self.time_unit_var = tk.StringVar(value='sec')
        time_unit_menu = ttk.Combobox(interval_frame, textvariable=self.time_unit_var, 
                                     values=['sec', 'min', 'hour'],
                                     state='readonly', width=6)
        time_unit_menu.pack(side='left', padx=2)
        
        self.monitor_btn = tk.Button(monitor_frame, text="Start Monitoring", 
                                     command=self.toggle_monitoring,
                                     bg='#00aa00', fg='white', relief='flat')
        self.monitor_btn.pack(fill='x', padx=5, pady=5)
        
        # Monitoring status indicator
        self.monitor_status_label = tk.Label(monitor_frame, text="Status: Idle", 
                                            bg='#3a3a3a', fg='#888888', 
                                            font=('Courier', 8))
        self.monitor_status_label.pack(pady=2)
        
        # Statistics
        stats_frame = tk.LabelFrame(left_panel, text="Statistics", 
                                   bg='#3a3a3a', fg='white', font=('Helvetica', 10, 'bold'))
        stats_frame.pack(fill='x', padx=10, pady=10)
        
        self.stats_label = tk.Label(stats_frame, text="Baseline files: 0\nMonitoring: Inactive", 
                                   bg='#3a3a3a', fg='#cccccc', justify='left')
        self.stats_label.pack(pady=5)
        
        # Right panel - Results
        right_panel = tk.Frame(main_container, bg='#3a3a3a')
        right_panel.pack(side='right', fill='both', expand=True, padx=(5, 0))
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill='both', expand=True)
        
        # Results Tab
        results_tab = tk.Frame(self.notebook, bg='#3a3a3a')
        self.notebook.add(results_tab, text='Verification Results')
        
        self.results_text = scrolledtext.ScrolledText(results_tab, wrap=tk.WORD,
                                                     bg='#1e1e1e', fg='#00ff00',
                                                     font=('Courier', 9),
                                                     insertbackground='white')
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Alerts Tab
        alerts_tab = tk.Frame(self.notebook, bg='#3a3a3a')
        self.notebook.add(alerts_tab, text='Alerts')
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_tab, wrap=tk.WORD,
                                                    bg='#1e1e1e', fg='#ff6600',
                                                    font=('Courier', 9),
                                                    insertbackground='white')
        self.alerts_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Log initial message
        self.log_result("File Integrity Monitor initialized.\nSelect a directory to begin.\n")
    
    def select_directory(self):
        """Select directory to monitor"""
        directory = filedialog.askdirectory(title="Select Directory to Monitor")
        if directory:
            self.monitored_directory = directory
            self.dir_label.config(text=f"...{directory[-40:]}" if len(directory) > 40 else directory)
            self.log_result(f"\n[{self.get_timestamp()}] Directory selected: {directory}\n")
    
    def create_baseline(self):
        """Create baseline for selected directory"""
        if not self.monitored_directory:
            messagebox.showwarning("Warning", "Please select a directory first")
            return
        
        self.log_result(f"\n[{self.get_timestamp()}] Creating baseline...\n")
        self.root.update()
        
        try:
            baseline, file_count = self.fim.create_baseline(self.monitored_directory, 
                                                           self.hash_var.get())
            self.fim.baseline = baseline
            
            if self.fim.save_baseline(baseline):
                self.log_result(f"✓ Baseline created successfully!\n")
                self.log_result(f"  Files scanned: {file_count}\n")
                self.log_result(f"  Hash algorithm: {self.hash_var.get()}\n")
                self.update_stats()
                messagebox.showinfo("Success", f"Baseline created with {file_count} files")
            else:
                self.log_result(f"✗ Failed to save baseline\n")
                messagebox.showerror("Error", "Failed to save baseline")
        except Exception as e:
            self.log_result(f"✗ Error creating baseline: {str(e)}\n")
            messagebox.showerror("Error", f"Error creating baseline: {str(e)}")
    
    def load_baseline(self):
        """Load existing baseline"""
        baseline = self.fim.load_baseline()
        if baseline:
            self.fim.baseline = baseline
            file_count = len(baseline)
            self.log_result(f"\n[{self.get_timestamp()}] Baseline loaded successfully\n")
            self.log_result(f"  Files in baseline: {file_count}\n")
            self.update_stats()
            messagebox.showinfo("Success", f"Baseline loaded with {file_count} files")
        else:
            self.log_result(f"\n[{self.get_timestamp()}] No baseline file found\n")
            messagebox.showwarning("Warning", "No baseline file found")
    
    def verify_integrity(self):
        """Verify file integrity"""
        if not self.monitored_directory:
            messagebox.showwarning("Warning", "Please select a directory first")
            return
        
        if not self.fim.baseline:
            messagebox.showwarning("Warning", "Please create or load a baseline first")
            return
        
        self.log_result(f"\n[{self.get_timestamp()}] Verifying file integrity...\n")
        self.root.update()
        
        try:
            results = self.fim.verify_integrity(self.monitored_directory)
            self.display_results(results)
        except Exception as e:
            self.log_result(f"✗ Error during verification: {str(e)}\n")
            messagebox.showerror("Error", f"Error during verification: {str(e)}")
    
    def display_results(self, results):
        """Display verification results"""
        if 'error' in results:
            self.log_result(f"✗ {results['error']}\n")
            return
        
        total_issues = len(results['modified']) + len(results['deleted']) + len(results['new'])
        
        self.log_result(f"\n{'='*70}\n")
        self.log_result(f"VERIFICATION RESULTS\n")
        self.log_result(f"{'='*70}\n\n")
        
        # Modified files
        if results['modified']:
            self.log_result(f"⚠️  MODIFIED FILES ({len(results['modified'])})\n")
            self.log_result(f"{'-'*70}\n")
            for item in results['modified']:
                self.log_result(f"  File: {item['path']}\n")
                self.log_result(f"  Baseline hash: {item['baseline_hash'][:16]}...\n")
                self.log_result(f"  Current hash:  {item['current_hash'][:16]}...\n")
                self.log_result(f"  Metadata changed: {item['metadata_changed']}\n\n")
        
        # Deleted files
        if results['deleted']:
            self.log_result(f"🗑️  DELETED FILES ({len(results['deleted'])})\n")
            self.log_result(f"{'-'*70}\n")
            for item in results['deleted']:
                self.log_result(f"  File: {item['path']}\n")
                self.log_result(f"  Baseline hash: {item['baseline_hash'][:16]}...\n\n")
        
        # New files
        if results['new']:
            self.log_result(f"➕ NEW FILES ({len(results['new'])})\n")
            self.log_result(f"{'-'*70}\n")
            for item in results['new']:
                self.log_result(f"  File: {item['path']}\n")
                self.log_result(f"  Hash: {item['hash'][:16]}...\n\n")
        
        # Errors
        if results['errors']:
            self.log_result(f"❌ ERRORS ({len(results['errors'])})\n")
            self.log_result(f"{'-'*70}\n")
            for item in results['errors']:
                self.log_result(f"  File: {item['path']}\n")
                self.log_result(f"  Error: {item['error']}\n\n")
        
        # Summary
        self.log_result(f"{'='*70}\n")
        self.log_result(f"SUMMARY\n")
        self.log_result(f"{'='*70}\n")
        self.log_result(f"  Modified: {len(results['modified'])}\n")
        self.log_result(f"  Deleted:  {len(results['deleted'])}\n")
        self.log_result(f"  New:      {len(results['new'])}\n")
        self.log_result(f"  Errors:   {len(results['errors'])}\n")
        
        if total_issues == 0:
            self.log_result(f"\n✓ All files verified successfully - No changes detected\n")
        else:
            self.log_result(f"\n⚠️  {total_issues} file integrity issues detected\n")
    
    def toggle_monitoring(self):
        """Toggle continuous monitoring"""
        if not self.monitored_directory:
            messagebox.showwarning("Warning", "Please select a directory first")
            return
        
        if not self.fim.baseline:
            messagebox.showwarning("Warning", "Please create or load a baseline first")
            return
        
        if not self.monitoring_active:
            try:
                interval_value = int(self.interval_var.get())
                time_unit = self.time_unit_var.get()
                
                # Convert to seconds based on time unit
                if time_unit == 'min':
                    interval = interval_value * 60
                    display_interval = f"{interval_value} minute(s)"
                elif time_unit == 'hour':
                    interval = interval_value * 3600
                    display_interval = f"{interval_value} hour(s)"
                else:  # sec
                    interval = interval_value
                    display_interval = f"{interval_value} second(s)"
                
                if interval < 1:
                    raise ValueError("Interval must be at least 1 second")
                
                self.monitoring_active = True
                self.fim.monitoring = True
                self.monitor_btn.config(text="Stop Monitoring", bg='#cc0000')
                self.monitor_status_label.config(text="Status: Starting...", fg='#ffaa00')
                
                def monitor_callback(results):
                    self.fim.alert_queue.put(results)
                
                self.fim.monitor_thread = threading.Thread(
                    target=self.fim.continuous_monitor,
                    args=(self.monitored_directory, interval, monitor_callback),
                    daemon=True
                )
                self.fim.monitor_thread.start()
                
                self.log_alert(f"[{self.get_timestamp()}] Monitoring started (interval: {display_interval})\n")
                self.log_alert(f"Waiting for first check...\n\n")
                self.update_stats()
                
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid interval: {str(e)}")
        else:
            self.monitoring_active = False
            self.fim.monitoring = False
            self.monitor_btn.config(text="Start Monitoring", bg='#00aa00')
            self.monitor_status_label.config(text="Status: Stopped", fg='#888888')
            self.log_alert(f"[{self.get_timestamp()}] Monitoring stopped\n\n")
            self.update_stats()
    
    def check_alert_queue(self):
        """Check for alerts from monitoring thread"""
        try:
            while True:
                results = self.fim.alert_queue.get_nowait()
                
                # Update status indicator
                current_time = self.get_timestamp()
                
                # Check if there are any changes
                total_issues = len(results.get('modified', [])) + len(results.get('deleted', [])) + len(results.get('new', []))
                
                if total_issues > 0:
                    # Display in alerts tab
                    self.log_alert(f"\n{'='*70}\n")
                    self.log_alert(f"[{current_time}] ⚠️  ALERT: File changes detected!\n")
                    self.log_alert(f"{'='*70}\n\n")
                    
                    # Modified files
                    if results['modified']:
                        self.log_alert(f"⚠️  MODIFIED FILES ({len(results['modified'])})\n")
                        self.log_alert(f"{'-'*70}\n")
                        for item in results['modified'][:5]:  # Show first 5
                            self.log_alert(f"  File: {item['path']}\n")
                            self.log_alert(f"  Hash changed: {item['baseline_hash'][:16]}... → {item['current_hash'][:16]}...\n\n")
                        if len(results['modified']) > 5:
                            self.log_alert(f"  ... and {len(results['modified']) - 5} more modified file(s)\n\n")
                    
                    # Deleted files
                    if results['deleted']:
                        self.log_alert(f"🗑️  DELETED FILES ({len(results['deleted'])})\n")
                        self.log_alert(f"{'-'*70}\n")
                        for item in results['deleted'][:5]:  # Show first 5
                            self.log_alert(f"  File: {item['path']}\n\n")
                        if len(results['deleted']) > 5:
                            self.log_alert(f"  ... and {len(results['deleted']) - 5} more deleted file(s)\n\n")
                    
                    # New files
                    if results['new']:
                        self.log_alert(f"➕ NEW FILES ({len(results['new'])})\n")
                        self.log_alert(f"{'-'*70}\n")
                        for item in results['new'][:5]:  # Show first 5
                            self.log_alert(f"  File: {item['path']}\n\n")
                        if len(results['new']) > 5:
                            self.log_alert(f"  ... and {len(results['new']) - 5} more new file(s)\n\n")
                    
                    # Summary
                    self.log_alert(f"{'='*70}\n")
                    self.log_alert(f"Total Issues: {total_issues}\n")
                    self.log_alert(f"{'='*70}\n\n")
                    
                    # Switch to alerts tab automatically
                    self.notebook.select(1)
                    
                    # Update status with alert
                    self.monitor_status_label.config(
                        text=f"⚠️ ALERT! {total_issues} issue(s) - {current_time[11:]}",
                        fg='#ff0000'
                    )
                else:
                    # No changes - just update last check time
                    self.monitor_status_label.config(
                        text=f"✓ Last check: {current_time[11:]} - No changes",
                        fg='#00ff00'
                    )
                
        except queue.Empty:
            pass
        
        self.root.after(500, self.check_alert_queue)
    
    def update_stats(self):
        """Update statistics display"""
        baseline_count = len(self.fim.baseline)
        monitoring_status = "Active" if self.monitoring_active else "Inactive"
        
        self.stats_label.config(
            text=f"Baseline files: {baseline_count}\nMonitoring: {monitoring_status}"
        )
    
    def log_result(self, message):
        """Log message to results tab"""
        self.results_text.insert(tk.END, message)
        self.results_text.see(tk.END)
    
    def log_alert(self, message):
        """Log message to alerts tab"""
        self.alerts_text.insert(tk.END, message)
        self.alerts_text.see(tk.END)
    
    def get_timestamp(self):
        """Get current timestamp"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def main():
    root = tk.Tk()
    app = FIMApplication(root)
    root.mainloop()


if __name__ == "__main__":
    main()