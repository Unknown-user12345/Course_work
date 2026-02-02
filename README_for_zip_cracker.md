# ZIP Password Cracker - Simplified Version

A streamlined, efficient GUI application for recovering passwords from encrypted ZIP files. This simplified version focuses on core functionality with a clean, easy-to-understand codebase.

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code Size](https://img.shields.io/badge/code-420%20lines-orange.svg)](zip_cracker_simple.py)

---

## 🎯 Overview

This tool helps recover forgotten passwords from encrypted ZIP archives using two proven attack methods:
- **Brute Force Attack**: Systematically tries all possible character combinations
- **Dictionary Attack**: Tests passwords from a wordlist with intelligent variations

**Perfect for**: Students, learners, and anyone needing a clean, functional password recovery tool.

---

## ✨ Features

### Core Functionality
- 🔓 **Two Attack Methods**: Brute force and dictionary attacks
- ⚡ **Multi-threaded**: Non-blocking UI with background processing
- 📊 **Real-time Statistics**: Live progress, speed, and attempt tracking
- 📝 **Activity Log**: Timestamped event logging
- 💾 **Wordlist Generator**: Built-in sample wordlist creation
- 📋 **Clipboard Support**: One-click password copying
- 🖥️ **Cross-Platform**: Works on Windows, Linux, and macOS

### User Interface
- Clean, intuitive tabbed interface
- Progress bar with visual feedback
- File selection dialogs
- Success notifications
- Simple, uncluttered design

---

## 📦 Installation

### Prerequisites
- **Python 3.7 or higher**
- **No external dependencies!** (Uses only Python standard library)

### Quick Start

1. **Download the file**
   ```bash
   # Download zip_cracker_simple.py
   ```

2. **Run the application**
   ```bash
   python zip_cracker_simple.py
   ```

   On Linux/Mac:
   ```bash
   python3 zip_cracker_simple.py
   ```

3. **That's it!** No installation, no dependencies, no setup.

### Linux Users
If tkinter is not installed:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch Linux
sudo pacman -S tk
```

---

## 🚀 Usage Guide

### Step 1: Select ZIP File
1. Click **"Select ZIP File"** button
2. Choose your encrypted ZIP archive
3. The file will be validated automatically

### Step 2: Choose Attack Method

#### **Method A: Brute Force Attack**

**Best for**: Short passwords (1-4 characters) when you have no information

**Steps**:
1. Go to **"Brute Force"** tab
2. Select character sets:
   - ☑️ Lowercase (a-z) - 26 characters
   - ☑️ Uppercase (A-Z) - 26 characters
   - ☑️ Digits (0-9) - 10 characters
   - ☐ Symbols (!@#$%...) - ~32 characters
3. Set password length:
   - **Min**: Starting length (e.g., 1)
   - **Max**: Maximum length (e.g., 4)
4. Click **"Start"**

**Time Estimates**:
- 4 lowercase chars: ~seconds
- 6 lowercase chars: ~minutes
- 4 alphanumeric: ~minutes
- 6 alphanumeric: ~hours

#### **Method B: Dictionary Attack**

**Best for**: Common passwords, known patterns

**Steps**:
1. Go to **"Dictionary"** tab
2. Either:
   - Click **"Select Wordlist"** to use your own wordlist
   - Click **"Generate Sample"** to create 20 common passwords
3. Enable options:
   - ☑️ **Try case variations** (password, Password, PASSWORD)
   - ☑️ **Add number suffixes** (password123, password2024)
4. Click **"Start"**

### Step 3: Monitor Progress

Watch the real-time statistics:
- **Attempts**: Number of passwords tested
- **Speed**: Passwords tested per second
- **Time**: Elapsed time

### Step 4: Success!

When the password is found:
1. A popup shows the password
2. Option to copy to clipboard
3. Full details in the log

---

## 📖 Detailed Examples

### Example 1: Quick Test (Dictionary)

```bash
# 1. Run the tool
python zip_cracker_simple.py

# 2. Select your ZIP file
Click "Select ZIP File" → choose encrypted.zip

# 3. Generate sample wordlist
Go to "Dictionary" tab → Click "Generate Sample"

# 4. Start cracking
Click "Start"

# Result: If password is common (admin, password, 123456), found in seconds!
```

### Example 2: Brute Force Short Password

```bash
# 1. Run the tool
python zip_cracker_simple.py

# 2. Select ZIP file
Click "Select ZIP File" → choose myfile.zip

# 3. Configure brute force
Go to "Brute Force" tab
- Check: Lowercase, Uppercase, Digits
- Min: 1, Max: 4

# 4. Start cracking
Click "Start"

# Result: Tries all combinations up to 4 characters
```

---

## 🎨 Interface Overview

```
┌──────────────────────────────────────────┐
│        ZIP Password Cracker              │
├──────────────────────────────────────────┤
│ ZIP File                                 │
│ [Select ZIP File]  myfile.zip            │
├──────────────────────────────────────────┤
│ ┌────────────┬──────────────┐            │
│ │Brute Force │ Dictionary   │            │
│ ├────────────┴──────────────┤            │
│ │ Character Set:             │            │
│ │ ☑ Lowercase (a-z)          │            │
│ │ ☑ Uppercase (A-Z)          │            │
│ │ ☑ Digits (0-9)             │            │
│ │ ☐ Symbols                  │            │
│ │                            │            │
│ │ Password Length:           │            │
│ │ Min: [1] Max: [4]          │            │
│ └────────────────────────────┘            │
├──────────────────────────────────────────┤
│ Progress                                 │
│ [████████████░░░░░░░░░]                  │
│ Status: Cracking...                      │
│ Attempts: 1,234 | Speed: 5,678 pwd/s ... │
├──────────────────────────────────────────┤
│ Log                                      │
│ [12:34:56] Started cracking...           │
│ [12:34:57] Brute force: 62 chars ...     │
│ [12:35:01] Testing passwords...          │
├──────────────────────────────────────────┤
│        [Start]        [Stop]             │
└──────────────────────────────────────────┘
```

---

## 🧪 Creating Test Files

To create encrypted ZIP files for testing:

### Option 1: Command Line (Linux/Mac)
```bash
echo "Secret message" > test.txt
zip -P password123 test.zip test.txt
rm test.txt
```

### Option 2: Command Line (Windows with 7-Zip)
```powershell
echo "Secret message" > test.txt
7z a -ppassword123 test.zip test.txt
del test.txt
```

### Option 3: Python Script
```bash
# Install pyminizip first
pip install pyminizip

# Use the provided script
python create_test_zips.py
```

### Option 4: GUI Tools
- **Windows**: WinRAR, 7-Zip
- **Linux**: File Roller, Ark
- **Mac**: Keka, The Unarchiver

---

## 🔧 Troubleshooting

### "No file selected"
**Issue**: Didn't select a ZIP file  
**Solution**: Click "Select ZIP File" and choose a .zip file

### "ZIP file is not encrypted!"
**Issue**: Selected ZIP has no password protection  
**Solution**: Create an encrypted ZIP or select a different file

### "Select or generate a wordlist!"
**Issue**: Dictionary attack needs a wordlist  
**Solution**: Click "Generate Sample" or "Select Wordlist"

### Very slow cracking
**Issue**: Password is long or complex  
**Solution**: 
- Use dictionary attack first
- Reduce brute force max length
- Try common password patterns

### Application won't start
**Issue**: Tkinter not installed (Linux)  
**Solution**: 
```bash
sudo apt-get install python3-tk  # Ubuntu/Debian
```

---

## 📊 Performance Guide

### Brute Force Complexity

| Charset | Size | 4 chars | 6 chars | 8 chars |
|---------|------|---------|---------|---------|
| Lowercase | 26 | 456K | 309M | 208B |
| Lower+Upper | 52 | 7.3M | 19.7B | 53T |
| Alphanumeric | 62 | 14.8M | 56.8B | 218T |
| All chars | 94 | 78.1M | 689B | 6,095T |

**Legend**: K=thousand, M=million, B=billion, T=trillion

### Recommended Settings

| Password Type | Method | Settings |
|---------------|--------|----------|
| Common words | Dictionary | Sample wordlist + variations |
| Short & simple | Brute Force | Lowercase, 1-4 chars |
| Known pattern | Dictionary | Custom wordlist |
| Complex | Hybrid/External | Use advanced tools |

### Expected Speed

On a modern CPU (Intel i7 / AMD Ryzen):
- **Dictionary**: 20,000 - 50,000 pwd/s
- **Brute Force**: 10,000 - 30,000 pwd/s

Speed varies based on:
- CPU performance
- ZIP encryption type (ZipCrypto vs AES-256)
- System load

---

## 🎓 Educational Use

This tool is excellent for learning:

### Concepts Demonstrated
- **Password Security**: Why length matters
- **Attack Methods**: Brute force vs dictionary
- **Complexity Analysis**: Time vs space tradeoffs
- **GUI Programming**: Tkinter basics
- **Multi-threading**: Background processing
- **File Handling**: ZIP archive manipulation

### For Students
- Clean, well-commented code
- Simple architecture
- Standard library only
- Easy to understand and modify
- Great for coursework projects

### Assignments & Projects
Perfect for:
- Security fundamentals courses
- Python programming projects
- Algorithm analysis studies
- Software development coursework

---

## 🔐 Security & Ethics

### ⚠️ LEGAL NOTICE

**This tool is for LEGAL and ETHICAL use only.**

### ✅ Legal Uses
- Recovering your own forgotten passwords
- Authorized security testing
- Educational purposes
- Security research with permission

### ❌ Illegal Uses
- Accessing others' files without permission
- Unauthorized data access
- Any form of hacking or cracking without consent

### Ethical Guidelines
1. **Only use on files you own** or have explicit permission to access
2. **Respect privacy laws** in your jurisdiction
3. **Do not distribute** recovered content without authorization
4. **Use responsibly** and follow applicable laws

**Disclaimer**: Users are solely responsible for compliance with all applicable laws. The developers assume no liability for misuse.

---

## 💡 Tips & Best Practices

### Strategy Tips
1. **Start with dictionary attack** - fastest for common passwords
2. **Use custom wordlists** - add names, dates, company terms
3. **Brute force is slow** - only for very short passwords
4. **Combine methods** - try dictionary first, then brute force

### Performance Tips
1. **Close other apps** - maximize CPU availability
2. **Start small** - test with low lengths first
3. **Use targeted wordlists** - quality over quantity
4. **Monitor speed** - if too slow, adjust strategy

### Wordlist Tips
1. **Download popular lists**: RockYou, SecLists
2. **Customize for target**: add relevant terms
3. **Remove duplicates**: `sort -u wordlist.txt`
4. **Filter by length**: `awk 'length($0) >= 6 && length($0) <= 12'`

---

## 📁 Project Structure

```
zip-cracker-simple/
├── zip_cracker_simple.py      # Main application (420 lines)
├── README.md                   # This file
├── create_test_zips.py         # Test file creator (optional)
├── VERSION_COMPARISON.md       # Comparison with full version
└── 3.3_Tools_and_Technologies.md  # Technical documentation
```

---

## 🛠️ Technical Details

### Architecture
- **Pattern**: Object-Oriented (single class)
- **Threading**: Main thread (GUI) + Worker thread (cracking)
- **GUI Framework**: Tkinter (event-driven)

### Algorithms
- **Brute Force**: Cartesian product generation (itertools)
- **Dictionary**: Linear search with variations
- **Complexity**: O(c^n) for brute force, O(n) for dictionary

### Dependencies
- **Core**: Python 3.7+ standard library
- **Optional**: pyminizip or pyzipper (for test file creation)

### Modules Used
| Module | Purpose |
|--------|---------|
| tkinter | GUI framework |
| zipfile | ZIP handling |
| threading | Background processing |
| itertools | Password generation |
| time | Performance tracking |
| os | File operations |
| string | Character sets |

---

## 📈 Roadmap & Future Enhancements

Possible improvements (for learning):
- [ ] Add pattern-based attacks
- [ ] Support for RAR/7z archives
- [ ] GPU acceleration
- [ ] Resume capability
- [ ] Password strength estimator
- [ ] Export results to file
- [ ] Multi-file batch processing

---

## 🤝 Contributing

This is a simplified educational tool. Feel free to:
- Fork and modify for your projects
- Use in coursework (with proper attribution)
- Create custom versions
- Share improvements

---

## 📝 License

This project is provided for educational purposes. Free to use, modify, and distribute for non-commercial purposes.

---

## 🙏 Acknowledgments

- Python community for excellent documentation
- Security researchers for methodology insights
- Open-source wordlist projects (RockYou, SecLists)

---

## 📞 Support

For issues or questions:
- Check the **Troubleshooting** section
- Review the **Usage Guide**
- Ensure you meet the **Prerequisites**

---

## 📚 Additional Resources

### Learning Resources
- [Python Documentation](https://docs.python.org/3/)
- [Tkinter Tutorial](https://docs.python.org/3/library/tkinter.html)
- [ZIP File Format](https://en.wikipedia.org/wiki/ZIP_(file_format))

### Wordlist Sources
- [RockYou](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [CrackStation](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)

### Security Tools
- [John the Ripper](https://www.openwall.com/john/)
- [Hashcat](https://hashcat.net/hashcat/)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)

---

## 🎯 Quick Reference

### Common Passwords to Test
```
password, 123456, admin, letmein, welcome
qwerty, abc123, password123, admin123, 12345678
```

### Useful Commands
```bash
# Run tool
python zip_cracker_simple.py

# Create test ZIP (Linux/Mac)
zip -P password123 test.zip file.txt

# Check if ZIP is encrypted (Linux)
unzip -l test.zip
```

### Keyboard Shortcuts
- `Ctrl+C` in terminal: Stop the application
- `Alt+F4` / `Cmd+Q`: Close window
- `Ctrl+V`: Paste (in text fields)

---

**Remember**: Use this tool responsibly and ethically. Strong passwords protect important data - this tool demonstrates why password security matters!

---

**Version**: 1.0 Simplified  
**Last Updated**: 2024  
**Author**: Educational Project  
**Status**: Stable & Production Ready

---

Made with ❤️ for learning and education
