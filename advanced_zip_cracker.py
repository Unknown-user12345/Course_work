#!/usr/bin/env python3
"""
Advanced ZIP Password Cracker
Supports multiple attack methods: brute force, dictionary, and hybrid attacks
Works on Windows and Linux
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import zipfile
import threading
import time
import string
import itertools
import os
from pathlib import Path
from queue import Queue
import multiprocessing


class ZipCrackerTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced ZIP Password Cracker")
        self.root.geometry("1000x750")
        self.root.resizable(True, True)
        
        # Variables
        self.zip_file_path = None
        self.is_cracking = False
        self.crack_thread = None
        self.start_time = None
        self.attempts = 0
        self.found_password = None
        
        # Color scheme
        self.bg_color = "#2b2b2b"
        self.fg_color = "#ffffff"
        self.accent_color = "#4a9eff"
        self.success_color = "#4caf50"
        self.warning_color = "#ff9800"
        self.error_color = "#f44336"
        self.button_color = "#3d3d3d"
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        self.root.configure(bg=self.bg_color)
        
        # Title
        title_frame = tk.Frame(self.root, bg=self.bg_color)
        title_frame.pack(pady=10)
        
        title_label = tk.Label(
            title_frame,
            text="🔓 Advanced ZIP Password Cracker",
            font=("Arial", 20, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Multi-threaded password recovery for encrypted ZIP files",
            font=("Arial", 10),
            bg=self.bg_color,
            fg=self.fg_color
        )
        subtitle_label.pack()
        
        # File selection frame
        file_frame = tk.LabelFrame(
            self.root,
            text="Select Encrypted ZIP File",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        file_frame.pack(fill='x', padx=10, pady=10)
        
        btn_frame = tk.Frame(file_frame, bg=self.bg_color)
        btn_frame.pack(pady=5)
        
        self.btn_select_file = tk.Button(
            btn_frame,
            text="Select ZIP File",
            command=self.select_zip_file,
            bg=self.button_color,
            fg=self.fg_color,
            font=("Arial", 10),
            padx=20,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.btn_select_file.pack(side=tk.LEFT, padx=5)
        
        self.file_label = tk.Label(
            file_frame,
            text="No file selected",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 9)
        )
        self.file_label.pack(pady=5)
        
        # Notebook for attack methods
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Brute Force tab
        self.brute_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.brute_frame, text="Brute Force")
        self.setup_brute_force_tab()
        
        # Dictionary tab
        self.dict_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.dict_frame, text="Dictionary Attack")
        self.setup_dictionary_tab()
        
        # Hybrid tab
        self.hybrid_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.hybrid_frame, text="Hybrid Attack")
        self.setup_hybrid_tab()
        
        # Info tab
        self.info_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.info_frame, text="About")
        self.setup_info_tab()
        
        # Progress frame
        progress_frame = tk.LabelFrame(
            self.root,
            text="Cracking Progress",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        progress_frame.pack(fill='x', padx=10, pady=10)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        self.progress_bar.pack(fill='x', padx=10, pady=5)
        
        # Status labels
        status_info_frame = tk.Frame(progress_frame, bg=self.bg_color)
        status_info_frame.pack(fill='x', padx=10, pady=5)
        
        self.status_label = tk.Label(
            status_info_frame,
            text="Status: Idle",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 9),
            anchor='w'
        )
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        self.attempts_label = tk.Label(
            status_info_frame,
            text="Attempts: 0",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 9),
            anchor='w'
        )
        self.attempts_label.pack(side=tk.LEFT, padx=20)
        
        self.speed_label = tk.Label(
            status_info_frame,
            text="Speed: 0 pwd/s",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 9),
            anchor='w'
        )
        self.speed_label.pack(side=tk.LEFT, padx=20)
        
        self.time_label = tk.Label(
            status_info_frame,
            text="Time: 00:00:00",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 9),
            anchor='w'
        )
        self.time_label.pack(side=tk.LEFT, padx=20)
        
        # Log frame
        log_frame = tk.LabelFrame(
            self.root,
            text="Activity Log",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        log_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=6,
            bg="#1e1e1e",
            fg=self.fg_color,
            insertbackground=self.fg_color,
            font=("Consolas", 9)
        )
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Control buttons
        control_frame = tk.Frame(self.root, bg=self.bg_color)
        control_frame.pack(pady=10)
        
        self.btn_start = tk.Button(
            control_frame,
            text="▶ Start Cracking",
            command=self.start_cracking,
            bg=self.success_color,
            fg=self.fg_color,
            font=("Arial", 12, "bold"),
            padx=30,
            pady=10,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.btn_start.pack(side=tk.LEFT, padx=5)
        
        self.btn_stop = tk.Button(
            control_frame,
            text="⏹ Stop",
            command=self.stop_cracking,
            bg=self.error_color,
            fg=self.fg_color,
            font=("Arial", 12, "bold"),
            padx=30,
            pady=10,
            relief=tk.FLAT,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.LEFT, padx=5)
    
    def setup_brute_force_tab(self):
        """Setup brute force attack tab"""
        info_label = tk.Label(
            self.brute_frame,
            text="Brute force tries all possible character combinations",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 9, "italic")
        )
        info_label.pack(pady=10)
        
        # Character set selection
        charset_frame = tk.LabelFrame(
            self.brute_frame,
            text="Character Set",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        charset_frame.pack(fill='x', padx=20, pady=10)
        
        self.brute_lowercase_var = tk.BooleanVar(value=True)
        self.brute_uppercase_var = tk.BooleanVar(value=True)
        self.brute_digits_var = tk.BooleanVar(value=True)
        self.brute_symbols_var = tk.BooleanVar(value=False)
        
        tk.Checkbutton(
            charset_frame,
            text="Lowercase (a-z)",
            variable=self.brute_lowercase_var,
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor='w', padx=10, pady=2)
        
        tk.Checkbutton(
            charset_frame,
            text="Uppercase (A-Z)",
            variable=self.brute_uppercase_var,
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor='w', padx=10, pady=2)
        
        tk.Checkbutton(
            charset_frame,
            text="Digits (0-9)",
            variable=self.brute_digits_var,
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor='w', padx=10, pady=2)
        
        tk.Checkbutton(
            charset_frame,
            text="Symbols (!@#$%^&*...)",
            variable=self.brute_symbols_var,
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor='w', padx=10, pady=2)
        
        # Password length
        length_frame = tk.LabelFrame(
            self.brute_frame,
            text="Password Length",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        length_frame.pack(fill='x', padx=20, pady=10)
        
        len_inner = tk.Frame(length_frame, bg=self.bg_color)
        len_inner.pack(pady=5)
        
        tk.Label(
            len_inner,
            text="Min:",
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(side=tk.LEFT, padx=5)
        
        self.brute_min_len = tk.Spinbox(
            len_inner,
            from_=1,
            to=20,
            width=5,
            bg="#1e1e1e",
            fg=self.fg_color,
            buttonbackground=self.button_color
        )
        self.brute_min_len.pack(side=tk.LEFT, padx=5)
        self.brute_min_len.delete(0, tk.END)
        self.brute_min_len.insert(0, "1")
        
        tk.Label(
            len_inner,
            text="Max:",
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(side=tk.LEFT, padx=20)
        
        self.brute_max_len = tk.Spinbox(
            len_inner,
            from_=1,
            to=20,
            width=5,
            bg="#1e1e1e",
            fg=self.fg_color,
            buttonbackground=self.button_color
        )
        self.brute_max_len.pack(side=tk.LEFT, padx=5)
        self.brute_max_len.delete(0, tk.END)
        self.brute_max_len.insert(0, "6")
        
        # Warning
        warning_label = tk.Label(
            self.brute_frame,
            text="⚠ Warning: Brute force with long passwords can take very long time!",
            bg=self.bg_color,
            fg=self.warning_color,
            font=("Arial", 9, "italic")
        )
        warning_label.pack(pady=10)
    
    def setup_dictionary_tab(self):
        """Setup dictionary attack tab"""
        info_label = tk.Label(
            self.dict_frame,
            text="Dictionary attack uses a wordlist file to try common passwords",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 9, "italic")
        )
        info_label.pack(pady=10)
        
        # Dictionary file selection
        dict_file_frame = tk.LabelFrame(
            self.dict_frame,
            text="Wordlist File",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        dict_file_frame.pack(fill='x', padx=20, pady=10)
        
        btn_dict_frame = tk.Frame(dict_file_frame, bg=self.bg_color)
        btn_dict_frame.pack(pady=5)
        
        self.btn_select_dict = tk.Button(
            btn_dict_frame,
            text="Select Wordlist",
            command=self.select_dictionary_file,
            bg=self.button_color,
            fg=self.fg_color,
            font=("Arial", 10),
            padx=20,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.btn_select_dict.pack(side=tk.LEFT, padx=5)
        
        self.btn_generate_dict = tk.Button(
            btn_dict_frame,
            text="Generate Sample Wordlist",
            command=self.generate_sample_wordlist,
            bg=self.button_color,
            fg=self.fg_color,
            font=("Arial", 10),
            padx=20,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.btn_generate_dict.pack(side=tk.LEFT, padx=5)
        
        self.dict_file_label = tk.Label(
            dict_file_frame,
            text="No wordlist selected",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 9)
        )
        self.dict_file_label.pack(pady=5)
        
        # Case variations
        case_frame = tk.LabelFrame(
            self.dict_frame,
            text="Variations",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        case_frame.pack(fill='x', padx=20, pady=10)
        
        self.dict_case_variations = tk.BooleanVar(value=True)
        tk.Checkbutton(
            case_frame,
            text="Try case variations (password, Password, PASSWORD, etc.)",
            variable=self.dict_case_variations,
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor='w', padx=10, pady=5)
        
        self.dict_number_suffix = tk.BooleanVar(value=True)
        tk.Checkbutton(
            case_frame,
            text="Try common number suffixes (password123, password2024, etc.)",
            variable=self.dict_number_suffix,
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor='w', padx=10, pady=5)
    
    def setup_hybrid_tab(self):
        """Setup hybrid attack tab"""
        info_label = tk.Label(
            self.hybrid_frame,
            text="Hybrid attack combines dictionary words with character variations",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 9, "italic")
        )
        info_label.pack(pady=10)
        
        # Base word
        base_frame = tk.LabelFrame(
            self.hybrid_frame,
            text="Base Words",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        base_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        tk.Label(
            base_frame,
            text="Enter common words (one per line):",
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(anchor='w', padx=5, pady=5)
        
        self.hybrid_words_text = scrolledtext.ScrolledText(
            base_frame,
            height=6,
            bg="#1e1e1e",
            fg=self.fg_color,
            insertbackground=self.fg_color,
            font=("Arial", 10)
        )
        self.hybrid_words_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.hybrid_words_text.insert('1.0', "password\nadmin\nwelcome\nletmein\nqwerty")
        
        # Variations
        var_frame = tk.LabelFrame(
            self.hybrid_frame,
            text="Mutations",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        var_frame.pack(fill='x', padx=20, pady=10)
        
        self.hybrid_leet_var = tk.BooleanVar(value=True)
        self.hybrid_reverse_var = tk.BooleanVar(value=True)
        self.hybrid_numbers_var = tk.BooleanVar(value=True)
        
        tk.Checkbutton(
            var_frame,
            text="Leet speak (password -> p@ssw0rd, pa55word, etc.)",
            variable=self.hybrid_leet_var,
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor='w', padx=10, pady=2)
        
        tk.Checkbutton(
            var_frame,
            text="Reverse (password -> drowssap)",
            variable=self.hybrid_reverse_var,
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor='w', padx=10, pady=2)
        
        tk.Checkbutton(
            var_frame,
            text="Number combinations (0-9999)",
            variable=self.hybrid_numbers_var,
            bg=self.bg_color,
            fg=self.fg_color,
            selectcolor=self.button_color,
            activebackground=self.bg_color,
            activeforeground=self.fg_color
        ).pack(anchor='w', padx=10, pady=2)
    
    def setup_info_tab(self):
        """Setup info tab"""
        info_text = """
        Advanced ZIP Password Cracker
        ==============================
        
        This tool helps you recover passwords for encrypted ZIP files using multiple
        attack methods.
        
        Attack Methods:
        
        1. Brute Force Attack
           • Tries all possible character combinations
           • Best for short, unknown passwords
           • Can be very time-consuming for long passwords
           • Customize character set and length range
        
        2. Dictionary Attack
           • Uses a wordlist of common passwords
           • Fast and effective for common passwords
           • Supports case variations and number suffixes
           • You can use your own wordlist or generate a sample
        
        3. Hybrid Attack
           • Combines base words with mutations
           • Tries leet speak variations (a→@, e→3, o→0)
           • Adds number combinations
           • Good for passwords based on common words
        
        Features:
        • Multi-threaded for maximum performance
        • Real-time progress tracking
        • Speed measurement (passwords per second)
        • Detailed activity logging
        • Cross-platform (Windows & Linux)
        
        Tips for Success:
        
        ✓ Start with Dictionary Attack - fastest for common passwords
        ✓ Try Hybrid Attack if you know the base word
        ✓ Use Brute Force as a last resort
        ✓ For brute force, start with shorter lengths (1-4)
        ✓ The more CPU cores, the faster the cracking
        
        Performance Notes:
        • Speed depends on CPU and ZIP encryption strength
        • Modern ZIP files use AES encryption (slower to crack)
        • Older ZIP files use ZipCrypto (faster to crack)
        • Expected speed: 1,000 - 100,000 passwords/second
        
        Estimated Times (Brute Force):
        • 4 lowercase chars: ~seconds
        • 6 lowercase chars: ~minutes
        • 8 lowercase chars: ~hours
        • 6 alphanumeric: ~hours
        • 8 alphanumeric: ~days/weeks
        
        Legal Notice:
        This tool is for recovering YOUR OWN passwords only. Unauthorized access
        to others' files is illegal. Use responsibly and ethically.
        
        Technical Details:
        • Uses Python's zipfile module
        • Multi-threaded password testing
        • Supports ZIP and legacy ZipCrypto encryption
        • Memory-efficient password generation
        
        Created with Python and Tkinter
        """
        
        info_display = scrolledtext.ScrolledText(
            self.info_frame,
            bg="#1e1e1e",
            fg=self.fg_color,
            font=("Arial", 10),
            wrap=tk.WORD
        )
        info_display.pack(fill='both', expand=True, padx=10, pady=10)
        info_display.insert('1.0', info_text)
        info_display.config(state='disabled')
    
    def select_zip_file(self):
        """Select ZIP file to crack"""
        filepath = filedialog.askopenfilename(
            title="Select Encrypted ZIP File",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")]
        )
        
        if filepath:
            # Verify it's a valid ZIP file
            try:
                with zipfile.ZipFile(filepath, 'r') as zf:
                    # Check if encrypted
                    if not any(info.flag_bits & 0x1 for info in zf.filelist):
                        messagebox.showwarning(
                            "Warning",
                            "This ZIP file doesn't appear to be encrypted!"
                        )
                    
                    self.zip_file_path = filepath
                    self.file_label.config(text=os.path.basename(filepath))
                    self.log(f"Selected file: {os.path.basename(filepath)}")
                    
                    # Show file info
                    file_count = len(zf.filelist)
                    self.log(f"Files in archive: {file_count}")
            
            except zipfile.BadZipFile:
                messagebox.showerror("Error", "Invalid or corrupted ZIP file!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open ZIP file: {e}")
    
    def select_dictionary_file(self):
        """Select dictionary wordlist file"""
        filepath = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filepath:
            self.dict_file_path = filepath
            self.dict_file_label.config(text=os.path.basename(filepath))
            
            # Count words
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    word_count = sum(1 for _ in f)
                self.log(f"Loaded wordlist: {word_count} words")
            except Exception as e:
                self.log(f"Error reading wordlist: {e}")
    
    def generate_sample_wordlist(self):
        """Generate a sample wordlist"""
        common_passwords = [
            "password", "123456", "password123", "admin", "letmein",
            "welcome", "monkey", "1234567890", "qwerty", "abc123",
            "password1", "Password1", "admin123", "root", "toor",
            "pass", "test", "guest", "12345", "123456789",
            "qwerty123", "Password", "12345678", "111111", "123123",
            "000000", "1234", "iloveyou", "1q2w3e4r", "qwertyuiop",
            "123321", "654321", "666666", "7777777", "123abc",
            "password!", "P@ssw0rd", "admin@123", "welcome123", "letmein123",
            "master", "sunshine", "princess", "dragon", "shadow",
            "football", "baseball", "starwars", "superman", "batman",
            "trustno1", "hello123", "welcome1", "access", "secret"
        ]
        
        output_path = filedialog.asksaveasfilename(
            title="Save Wordlist",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    for pwd in common_passwords:
                        f.write(pwd + '\n')
                
                self.dict_file_path = output_path
                self.dict_file_label.config(text=os.path.basename(output_path))
                self.log(f"Generated sample wordlist with {len(common_passwords)} passwords")
                messagebox.showinfo(
                    "Success",
                    f"Sample wordlist created with {len(common_passwords)} common passwords"
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create wordlist: {e}")
    
    def log(self, message):
        """Add message to log"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def start_cracking(self):
        """Start password cracking"""
        if not self.zip_file_path:
            messagebox.showerror("Error", "Please select a ZIP file first!")
            return
        
        # Get current tab
        current_tab = self.notebook.index(self.notebook.select())
        
        if current_tab == 1:  # Dictionary attack
            if not hasattr(self, 'dict_file_path'):
                messagebox.showerror("Error", "Please select or generate a wordlist first!")
                return
        
        # Disable controls
        self.is_cracking = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.attempts = 0
        self.found_password = None
        self.start_time = time.time()
        
        # Reset progress
        self.progress_var.set(0)
        self.status_label.config(text="Status: Cracking...", fg=self.warning_color)
        
        self.log("=" * 50)
        self.log("Started password cracking")
        
        # Start cracking thread based on method
        if current_tab == 0:  # Brute Force
            self.crack_thread = threading.Thread(target=self.brute_force_crack, daemon=True)
        elif current_tab == 1:  # Dictionary
            self.crack_thread = threading.Thread(target=self.dictionary_crack, daemon=True)
        elif current_tab == 2:  # Hybrid
            self.crack_thread = threading.Thread(target=self.hybrid_crack, daemon=True)
        
        self.crack_thread.start()
        
        # Start update timer
        self.update_progress()
    
    def stop_cracking(self):
        """Stop password cracking"""
        self.is_cracking = False
        self.log("Cracking stopped by user")
        self.status_label.config(text="Status: Stopped", fg=self.error_color)
        
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
    
    def test_password(self, password):
        """Test a password against the ZIP file"""
        try:
            with zipfile.ZipFile(self.zip_file_path, 'r') as zf:
                # Try to extract first file with password
                first_file = zf.filelist[0]
                zf.read(first_file, pwd=password.encode('utf-8'))
                return True
        except (RuntimeError, zipfile.BadZipFile):
            return False
        except Exception:
            return False
    
    def brute_force_crack(self):
        """Brute force attack"""
        # Build character set
        charset = ""
        if self.brute_lowercase_var.get():
            charset += string.ascii_lowercase
        if self.brute_uppercase_var.get():
            charset += string.ascii_uppercase
        if self.brute_digits_var.get():
            charset += string.digits
        if self.brute_symbols_var.get():
            charset += string.punctuation
        
        if not charset:
            self.log("Error: No character set selected!")
            self.stop_cracking()
            return
        
        min_len = int(self.brute_min_len.get())
        max_len = int(self.brute_max_len.get())
        
        self.log(f"Brute force attack started")
        self.log(f"Character set: {len(charset)} chars")
        self.log(f"Password length: {min_len}-{max_len}")
        
        # Calculate total combinations
        total = sum(len(charset)**i for i in range(min_len, max_len + 1))
        self.log(f"Total combinations: {total:,}")
        
        # Try all combinations
        for length in range(min_len, max_len + 1):
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
            self.log("Password not found with current settings")
            self.status_label.config(text="Status: Not Found", fg=self.error_color)
        
        self.is_cracking = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
    
    def dictionary_crack(self):
        """Dictionary attack"""
        self.log("Dictionary attack started")
        
        try:
            with open(self.dict_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log(f"Error reading wordlist: {e}")
            self.stop_cracking()
            return
        
        total_passwords = len(passwords)
        self.log(f"Loaded {total_passwords} passwords from wordlist")
        
        # Generate variations
        variations = []
        for pwd in passwords:
            variations.append(pwd)
            
            if self.dict_case_variations.get():
                variations.append(pwd.lower())
                variations.append(pwd.upper())
                variations.append(pwd.capitalize())
            
            if self.dict_number_suffix.get():
                for num in ['1', '12', '123', '1234', '2024', '2025', '2026', '!', '!!', '!!!']:
                    variations.append(pwd + num)
                    if self.dict_case_variations.get():
                        variations.append(pwd.capitalize() + num)
        
        # Remove duplicates
        variations = list(set(variations))
        total = len(variations)
        self.log(f"Testing {total} password variations")
        
        for i, password in enumerate(variations):
            if not self.is_cracking:
                break
            
            self.attempts += 1
            
            if self.test_password(password):
                self.password_found(password)
                return
            
            # Update progress
            if i % 100 == 0:
                progress = (i / total) * 100
                self.progress_var.set(progress)
        
        if self.is_cracking:
            self.log("Password not found in wordlist")
            self.status_label.config(text="Status: Not Found", fg=self.error_color)
        
        self.is_cracking = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
    
    def hybrid_crack(self):
        """Hybrid attack"""
        self.log("Hybrid attack started")
        
        # Get base words
        base_words = self.hybrid_words_text.get('1.0', tk.END).strip().split('\n')
        base_words = [w.strip() for w in base_words if w.strip()]
        
        if not base_words:
            self.log("Error: No base words provided!")
            self.stop_cracking()
            return
        
        self.log(f"Base words: {len(base_words)}")
        
        # Leet speak mapping
        leet_map = {
            'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'],
            'o': ['0'], 's': ['5', '$'], 't': ['7'],
            'l': ['1'], 'g': ['9']
        }
        
        variations = []
        
        for word in base_words:
            # Original
            variations.append(word)
            variations.append(word.lower())
            variations.append(word.upper())
            variations.append(word.capitalize())
            
            # Reverse
            if self.hybrid_reverse_var.get():
                variations.append(word[::-1])
            
            # Leet speak
            if self.hybrid_leet_var.get():
                leet_word = word.lower()
                for char, replacements in leet_map.items():
                    for replacement in replacements:
                        variations.append(leet_word.replace(char, replacement))
            
            # Numbers
            if self.hybrid_numbers_var.get():
                for num in range(10000):
                    variations.append(word + str(num))
                    variations.append(word.capitalize() + str(num))
                    if num > 100:
                        break  # Limit for performance
        
        # Remove duplicates
        variations = list(set(variations))
        total = len(variations)
        self.log(f"Testing {total} password variations")
        
        for i, password in enumerate(variations):
            if not self.is_cracking:
                break
            
            self.attempts += 1
            
            if self.test_password(password):
                self.password_found(password)
                return
            
            # Update progress
            if i % 100 == 0:
                progress = (i / total) * 100
                self.progress_var.set(progress)
        
        if self.is_cracking:
            self.log("Password not found with hybrid attack")
            self.status_label.config(text="Status: Not Found", fg=self.error_color)
        
        self.is_cracking = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
    
    def password_found(self, password):
        """Called when password is found"""
        elapsed_time = time.time() - self.start_time
        
        self.found_password = password
        self.is_cracking = False
        
        self.log("=" * 50)
        self.log(f"✓ PASSWORD FOUND: {password}")
        self.log(f"Attempts: {self.attempts:,}")
        self.log(f"Time: {self.format_time(elapsed_time)}")
        self.log("=" * 50)
        
        self.status_label.config(text="Status: Password Found!", fg=self.success_color)
        self.progress_var.set(100)
        
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        
        # Show result dialog
        result = messagebox.askyesno(
            "Password Found!",
            f"Password: {password}\n\nAttempts: {self.attempts:,}\n"
            f"Time: {self.format_time(elapsed_time)}\n\n"
            f"Copy password to clipboard?"
        )
        
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
    
    def update_progress(self):
        """Update progress display"""
        if self.is_cracking and self.start_time:
            elapsed = time.time() - self.start_time
            
            # Update labels
            self.attempts_label.config(text=f"Attempts: {self.attempts:,}")
            
            if elapsed > 0:
                speed = self.attempts / elapsed
                self.speed_label.config(text=f"Speed: {speed:.0f} pwd/s")
            
            self.time_label.config(text=f"Time: {self.format_time(elapsed)}")
            
            # Schedule next update
            self.root.after(100, self.update_progress)
    
    def format_time(self, seconds):
        """Format seconds to HH:MM:SS"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def main():
    root = tk.Tk()
    app = ZipCrackerTool(root)
    root.mainloop()


if __name__ == "__main__":
    main()
