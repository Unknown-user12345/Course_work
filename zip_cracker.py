#!/usr/bin/env python3
"""
ZIP Password Cracker - Simplified Version
Streamlined GUI with core functionality
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import zipfile
import threading
import time
import string
import itertools
import os


class ZipCracker:
    def __init__(self, root):
        self.root = root
        self.root.title("ZIP Password Cracker")
        self.root.geometry("800x600")
        
        self.zip_file_path = None
        self.is_cracking = False
        self.start_time = None
        self.attempts = 0
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup simplified user interface"""
        # Title
        tk.Label(
            self.root,
            text="ZIP Password Cracker",
            font=("Arial", 16, "bold")
        ).pack(pady=10)
        
        # File selection
        file_frame = tk.LabelFrame(self.root, text="ZIP File", font=("Arial", 10, "bold"))
        file_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Button(
            file_frame,
            text="Select ZIP File",
            command=self.select_zip_file,
            width=15
        ).pack(side=tk.LEFT, padx=10, pady=5)
        
        self.file_label = tk.Label(file_frame, text="No file selected")
        self.file_label.pack(side=tk.LEFT, padx=10)
        
        # Attack method tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Brute Force tab
        self.brute_frame = tk.Frame(self.notebook)
        self.notebook.add(self.brute_frame, text="Brute Force")
        self.setup_brute_force()
        
        # Dictionary tab
        self.dict_frame = tk.Frame(self.notebook)
        self.notebook.add(self.dict_frame, text="Dictionary")
        self.setup_dictionary()
        
        # Progress section
        progress_frame = tk.LabelFrame(self.root, text="Progress", font=("Arial", 10, "bold"))
        progress_frame.pack(fill='x', padx=10, pady=5)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.pack(fill='x', padx=10, pady=5)
        
        self.status_label = tk.Label(progress_frame, text="Status: Idle")
        self.status_label.pack(pady=2)
        
        self.stats_label = tk.Label(progress_frame, text="Attempts: 0 | Speed: 0 pwd/s | Time: 00:00")
        self.stats_label.pack(pady=2)
        
        # Log
        log_frame = tk.LabelFrame(self.root, text="Log", font=("Arial", 10, "bold"))
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, font=("Consolas", 9))
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Control buttons
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        self.btn_start = tk.Button(
            btn_frame,
            text="Start",
            command=self.start_cracking,
            bg="#4caf50",
            fg="white",
            width=15,
            font=("Arial", 10, "bold")
        )
        self.btn_start.pack(side=tk.LEFT, padx=5)
        
        self.btn_stop = tk.Button(
            btn_frame,
            text="Stop",
            command=self.stop_cracking,
            bg="#f44336",
            fg="white",
            width=15,
            font=("Arial", 10, "bold"),
            state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.LEFT, padx=5)
    
    def setup_brute_force(self):
        """Setup brute force options"""
        # Character sets
        tk.Label(self.brute_frame, text="Character Set:", font=("Arial", 10, "bold")).pack(anchor='w', padx=10, pady=5)
        
        self.brute_lower = tk.BooleanVar(value=True)
        self.brute_upper = tk.BooleanVar(value=True)
        self.brute_digits = tk.BooleanVar(value=True)
        self.brute_symbols = tk.BooleanVar(value=False)
        
        tk.Checkbutton(self.brute_frame, text="Lowercase (a-z)", variable=self.brute_lower).pack(anchor='w', padx=20)
        tk.Checkbutton(self.brute_frame, text="Uppercase (A-Z)", variable=self.brute_upper).pack(anchor='w', padx=20)
        tk.Checkbutton(self.brute_frame, text="Digits (0-9)", variable=self.brute_digits).pack(anchor='w', padx=20)
        tk.Checkbutton(self.brute_frame, text="Symbols", variable=self.brute_symbols).pack(anchor='w', padx=20)
        
        # Length
        tk.Label(self.brute_frame, text="Password Length:", font=("Arial", 10, "bold")).pack(anchor='w', padx=10, pady=5)
        
        length_frame = tk.Frame(self.brute_frame)
        length_frame.pack(anchor='w', padx=20)
        
        tk.Label(length_frame, text="Min:").pack(side=tk.LEFT)
        self.min_len = tk.Spinbox(length_frame, from_=1, to=10, width=5)
        self.min_len.pack(side=tk.LEFT, padx=5)
        self.min_len.delete(0, tk.END)
        self.min_len.insert(0, "1")
        
        tk.Label(length_frame, text="Max:").pack(side=tk.LEFT, padx=(10, 0))
        self.max_len = tk.Spinbox(length_frame, from_=1, to=10, width=5)
        self.max_len.pack(side=tk.LEFT, padx=5)
        self.max_len.delete(0, tk.END)
        self.max_len.insert(0, "4")
    
    def setup_dictionary(self):
        """Setup dictionary attack options"""
        tk.Label(self.dict_frame, text="Wordlist File:", font=("Arial", 10, "bold")).pack(anchor='w', padx=10, pady=5)
        
        btn_frame = tk.Frame(self.dict_frame)
        btn_frame.pack(anchor='w', padx=20, pady=5)
        
        tk.Button(btn_frame, text="Select Wordlist", command=self.select_wordlist, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Generate Sample", command=self.generate_wordlist, width=15).pack(side=tk.LEFT, padx=5)
        
        self.dict_label = tk.Label(self.dict_frame, text="No wordlist selected")
        self.dict_label.pack(anchor='w', padx=20, pady=5)
        
        tk.Label(self.dict_frame, text="Options:", font=("Arial", 10, "bold")).pack(anchor='w', padx=10, pady=5)
        
        self.dict_case = tk.BooleanVar(value=True)
        self.dict_numbers = tk.BooleanVar(value=True)
        
        tk.Checkbutton(self.dict_frame, text="Try case variations", variable=self.dict_case).pack(anchor='w', padx=20)
        tk.Checkbutton(self.dict_frame, text="Add number suffixes", variable=self.dict_numbers).pack(anchor='w', padx=20)
    
    def select_zip_file(self):
        """Select ZIP file"""
        filepath = filedialog.askopenfilename(
            title="Select ZIP File",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                with zipfile.ZipFile(filepath, 'r') as zf:
                    if not any(info.flag_bits & 0x1 for info in zf.filelist):
                        messagebox.showwarning("Warning", "ZIP file is not encrypted!")
                    
                    self.zip_file_path = filepath
                    self.file_label.config(text=os.path.basename(filepath))
                    self.log(f"Selected: {os.path.basename(filepath)}")
            except:
                messagebox.showerror("Error", "Invalid ZIP file!")
    
    def select_wordlist(self):
        """Select wordlist file"""
        filepath = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filepath:
            self.dict_file_path = filepath
            self.dict_label.config(text=os.path.basename(filepath))
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    count = sum(1 for _ in f)
                self.log(f"Loaded wordlist: {count} words")
            except:
                pass
    
    def generate_wordlist(self):
        """Generate sample wordlist"""
        passwords = [
            "password", "123456", "admin", "letmein", "welcome",
            "qwerty", "abc123", "password123", "admin123", "12345678",
            "pass", "test", "guest", "root", "toor",
            "Password1", "P@ssw0rd", "welcome123", "password1", "1234"
        ]
        
        filepath = filedialog.asksaveasfilename(
            title="Save Wordlist",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                for pwd in passwords:
                    f.write(pwd + '\n')
            
            self.dict_file_path = filepath
            self.dict_label.config(text=os.path.basename(filepath))
            self.log(f"Generated wordlist with {len(passwords)} passwords")
    
    def log(self, message):
        """Add message to log"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def start_cracking(self):
        """Start password cracking"""
        if not self.zip_file_path:
            messagebox.showerror("Error", "Select a ZIP file first!")
            return
        
        tab = self.notebook.index(self.notebook.select())
        
        if tab == 1 and not hasattr(self, 'dict_file_path'):
            messagebox.showerror("Error", "Select or generate a wordlist!")
            return
        
        self.is_cracking = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.attempts = 0
        self.start_time = time.time()
        
        self.progress_bar.start()
        self.status_label.config(text="Status: Cracking...")
        self.log("Started cracking...")
        
        if tab == 0:
            threading.Thread(target=self.brute_force_attack, daemon=True).start()
        else:
            threading.Thread(target=self.dictionary_attack, daemon=True).start()
        
        self.update_stats()
    
    def stop_cracking(self):
        """Stop cracking"""
        self.is_cracking = False
        self.progress_bar.stop()
        self.log("Stopped by user")
        self.status_label.config(text="Status: Stopped")
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
    
    def test_password(self, password):
        """Test password"""
        try:
            with zipfile.ZipFile(self.zip_file_path, 'r') as zf:
                zf.read(zf.filelist[0], pwd=password.encode('utf-8'))
                return True
        except:
            return False
    
    def brute_force_attack(self):
        """Brute force attack"""
        charset = ""
        if self.brute_lower.get():
            charset += string.ascii_lowercase
        if self.brute_upper.get():
            charset += string.ascii_uppercase
        if self.brute_digits.get():
            charset += string.digits
        if self.brute_symbols.get():
            charset += string.punctuation
        
        if not charset:
            self.log("Error: No character set selected")
            self.stop_cracking()
            return
        
        min_l = int(self.min_len.get())
        max_l = int(self.max_len.get())
        
        self.log(f"Brute force: {len(charset)} chars, length {min_l}-{max_l}")
        
        for length in range(min_l, max_l + 1):
            if not self.is_cracking:
                break
            
            for combo in itertools.product(charset, repeat=length):
                if not self.is_cracking:
                    break
                
                password = ''.join(combo)
                self.attempts += 1
                
                if self.test_password(password):
                    self.password_found(password)
                    return
        
        if self.is_cracking:
            self.log("Password not found")
            self.status_label.config(text="Status: Not Found")
        
        self.finish_cracking()
    
    def dictionary_attack(self):
        """Dictionary attack"""
        try:
            with open(self.dict_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        except:
            self.log("Error reading wordlist")
            self.stop_cracking()
            return
        
        self.log(f"Dictionary attack: {len(words)} base words")
        
        passwords = []
        for word in words:
            passwords.append(word)
            
            if self.dict_case.get():
                passwords.extend([word.lower(), word.upper(), word.capitalize()])
            
            if self.dict_numbers.get():
                for num in ['1', '123', '2024', '2025', '!']:
                    passwords.append(word + num)
        
        passwords = list(set(passwords))
        self.log(f"Testing {len(passwords)} variations")
        
        for password in passwords:
            if not self.is_cracking:
                break
            
            self.attempts += 1
            
            if self.test_password(password):
                self.password_found(password)
                return
        
        if self.is_cracking:
            self.log("Password not found")
            self.status_label.config(text="Status: Not Found")
        
        self.finish_cracking()
    
    def password_found(self, password):
        """Password found"""
        elapsed = time.time() - self.start_time
        
        self.is_cracking = False
        self.progress_bar.stop()
        
        self.log("=" * 40)
        self.log(f"PASSWORD FOUND: {password}")
        self.log(f"Attempts: {self.attempts:,}")
        self.log(f"Time: {self.format_time(elapsed)}")
        self.log("=" * 40)
        
        self.status_label.config(text="Status: Found!")
        
        if messagebox.askyesno("Success!", f"Password: {password}\n\nCopy to clipboard?"):
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
        
        self.finish_cracking()
    
    def finish_cracking(self):
        """Finish cracking"""
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.progress_bar.stop()
    
    def update_stats(self):
        """Update statistics"""
        if self.is_cracking and self.start_time:
            elapsed = time.time() - self.start_time
            speed = self.attempts / elapsed if elapsed > 0 else 0
            
            self.stats_label.config(
                text=f"Attempts: {self.attempts:,} | Speed: {speed:.0f} pwd/s | Time: {self.format_time(elapsed)}"
            )
            
            self.root.after(100, self.update_stats)
    
    def format_time(self, seconds):
        """Format time"""
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"


def main():
    root = tk.Tk()
    app = ZipCracker(root)
    root.mainloop()


if __name__ == "__main__":
    main()