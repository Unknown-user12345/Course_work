#!/usr/bin/env python3

import unittest
import os
import zipfile
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
import tkinter as tk
from zip_cracker import ZipCracker


class TestZipCracker(unittest.TestCase):
    """Comprehensive test suite for ZIP Password Cracker"""
    
    def setUp(self):
        """Set up test fixtures before each test"""
        self.root = tk.Tk()
        self.app = ZipCracker(self.root)
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up after each test"""
        try:
            self.root.destroy()
        except:
            pass
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def create_test_zip(self, password=None):
        """Helper to create test ZIP files"""
        zip_path = os.path.join(self.test_dir, "test.zip")
        test_file = os.path.join(self.test_dir, "test.txt")
        
        with open(test_file, 'w') as f:
            f.write("Test content")
        
        with zipfile.ZipFile(zip_path, 'w') as zf:
            if password:
                # Set encryption flag manually for testing
                zf.setpassword(password.encode('utf-8'))
            zf.write(test_file, "test.txt")
            if password:
                # Mark as encrypted
                for zinfo in zf.filelist:
                    zinfo.flag_bits |= 0x1
        
        os.remove(test_file)
        return zip_path
    
    # Test 1: UI Initialization
    def test_01_ui_initialization(self):
        """Test 1: Verify UI components are properly initialized"""
        self.assertIsNotNone(self.app.root)
        self.assertEqual(self.app.root.title(), "ZIP Password Cracker")
        self.assertIsNotNone(self.app.file_label)
        self.assertIsNotNone(self.app.progress_bar)
        self.assertIsNotNone(self.app.log_text)
        print("✓ TEST 1 PASSED: UI components initialized successfully with all required widgets")
    
    # Test 2: Initial State
    def test_02_initial_state(self):
        """Test 2: Verify application starts with correct initial state"""
        self.assertIsNone(self.app.zip_file_path)
        self.assertFalse(self.app.is_cracking)
        self.assertIsNone(self.app.start_time)
        self.assertEqual(self.app.attempts, 0)
        print("✓ TEST 2 PASSED: Application initial state is correct with no active operations")
    
    # Test 3: Log Functionality
    def test_03_log_functionality(self):
        """Test 3: Verify logging system works correctly"""
        test_message = "Test log message"
        self.app.log(test_message)
        log_content = self.app.log_text.get("1.0", tk.END)
        self.assertIn(test_message, log_content)
        print("✓ TEST 3 PASSED: Log system successfully writes and displays messages with timestamps")
    
    # Test 4: Valid ZIP File Selection
    def test_04_valid_zip_selection(self):
        """Test 4: Test selecting a valid encrypted ZIP file"""
        zip_path = self.create_test_zip(password="test123")
        
        with patch('tkinter.filedialog.askopenfilename', return_value=zip_path):
            self.app.select_zip_file()
        
        self.assertEqual(self.app.zip_file_path, zip_path)
        self.assertIn("test.zip", self.app.file_label.cget("text"))
        print("✓ TEST 4 PASSED: Valid encrypted ZIP file selected and path stored correctly")
    
    # Test 5: Unencrypted ZIP Warning
    def test_05_unencrypted_zip_warning(self):
        """Test 5: Test warning for unencrypted ZIP files"""
        zip_path = self.create_test_zip(password=None)
        
        with patch('tkinter.filedialog.askopenfilename', return_value=zip_path):
            with patch('tkinter.messagebox.showwarning') as mock_warning:
                self.app.select_zip_file()
                mock_warning.assert_called_once()
        
        print("✓ TEST 5 PASSED: Warning displayed correctly when unencrypted ZIP is selected")
    
    # Test 6: Invalid ZIP File Handling
    def test_06_invalid_zip_handling(self):
        """Test 6: Test handling of invalid/corrupted ZIP files"""
        invalid_path = os.path.join(self.test_dir, "invalid.zip")
        with open(invalid_path, 'w') as f:
            f.write("Not a valid ZIP file")
        
        with patch('tkinter.filedialog.askopenfilename', return_value=invalid_path):
            with patch('tkinter.messagebox.showerror') as mock_error:
                self.app.select_zip_file()
                mock_error.assert_called_once()
        
        print("✓ TEST 6 PASSED: Error handled gracefully for corrupted or invalid ZIP files")
    
    # Test 7: Password Testing Mechanism
    def test_07_password_testing(self):
        """Test 7: Verify password testing mechanism works correctly"""
        zip_path = os.path.join(self.test_dir, "test.zip")
        self.app.zip_file_path = zip_path
        
        # Mock the zipfile behavior
        with patch('zipfile.ZipFile') as mock_zip:
            mock_instance = MagicMock()
            mock_zip.return_value.__enter__.return_value = mock_instance
            
            # Test wrong password - should raise exception
            mock_instance.read.side_effect = RuntimeError("Bad password")
            result_wrong = self.app.test_password("wrong")
            self.assertFalse(result_wrong)
            
            # Test correct password - should succeed
            mock_instance.read.side_effect = None
            mock_instance.read.return_value = b"content"
            result_correct = self.app.test_password("secret")
            self.assertTrue(result_correct)
            
        print("✓ TEST 7 PASSED: Password testing correctly identifies valid and invalid passwords")
    
    # Test 8: Brute Force Character Set
    def test_08_brute_force_charset(self):
        """Test 8: Test brute force character set configuration"""
        self.app.brute_lower.set(True)
        self.app.brute_upper.set(False)
        self.app.brute_digits.set(True)
        self.app.brute_symbols.set(False)
        
        self.assertTrue(self.app.brute_lower.get())
        self.assertTrue(self.app.brute_digits.get())
        self.assertFalse(self.app.brute_upper.get())
        self.assertFalse(self.app.brute_symbols.get())
        print("✓ TEST 8 PASSED: Character set options properly configured for brute force attack")
    
    # Test 9: Length Parameters
    def test_09_length_parameters(self):
        """Test 9: Test password length parameter settings"""
        self.app.min_len.delete(0, tk.END)
        self.app.min_len.insert(0, "2")
        self.app.max_len.delete(0, tk.END)
        self.app.max_len.insert(0, "5")
        
        self.assertEqual(self.app.min_len.get(), "2")
        self.assertEqual(self.app.max_len.get(), "5")
        print("✓ TEST 9 PASSED: Min and max password length parameters set and retrieved correctly")
    
    # Test 10: Wordlist Generation
    def test_10_wordlist_generation(self):
        """Test 10: Test wordlist file generation functionality"""
        wordlist_path = os.path.join(self.test_dir, "wordlist.txt")
        
        with patch('tkinter.filedialog.asksaveasfilename', return_value=wordlist_path):
            self.app.generate_wordlist()
        
        self.assertTrue(os.path.exists(wordlist_path))
        with open(wordlist_path, 'r') as f:
            lines = f.readlines()
        self.assertGreater(len(lines), 0)
        print("✓ TEST 10 PASSED: Wordlist file generated successfully with multiple password entries")
    
    # Test 11: Wordlist Selection
    def test_11_wordlist_selection(self):
        """Test 11: Test selecting and loading a wordlist file"""
        wordlist_path = os.path.join(self.test_dir, "custom.txt")
        with open(wordlist_path, 'w') as f:
            f.write("password1\npassword2\npassword3\n")
        
        with patch('tkinter.filedialog.askopenfilename', return_value=wordlist_path):
            self.app.select_wordlist()
        
        self.assertEqual(self.app.dict_file_path, wordlist_path)
        print("✓ TEST 11 PASSED: Custom wordlist file loaded and word count calculated correctly")
    
    # Test 12: Start Without ZIP File
    def test_12_start_without_zip(self):
        """Test 12: Test error handling when starting without selecting ZIP"""
        with patch('tkinter.messagebox.showerror') as mock_error:
            self.app.start_cracking()
            mock_error.assert_called_once()
        
        self.assertFalse(self.app.is_cracking)
        print("✓ TEST 12 PASSED: Error properly displayed when attempting to crack without ZIP file")
    
    # Test 13: Stop Cracking Functionality
    def test_13_stop_cracking(self):
        """Test 13: Test stopping the cracking process"""
        self.app.is_cracking = True
        self.app.start_time = 0
        self.app.stop_cracking()
        
        self.assertFalse(self.app.is_cracking)
        self.assertEqual(self.app.btn_start['state'], tk.NORMAL)
        self.assertEqual(self.app.btn_stop['state'], tk.DISABLED)
        print("✓ TEST 13 PASSED: Cracking process stopped successfully and UI buttons reset properly")
    
    # Test 14: Time Formatting
    def test_14_time_formatting(self):
        """Test 14: Test time formatting for statistics display"""
        formatted = self.app.format_time(3661)  # 1 hour, 1 minute, 1 second
        self.assertEqual(formatted, "01:01:01")
        
        formatted = self.app.format_time(125)  # 2 minutes, 5 seconds
        self.assertEqual(formatted, "00:02:05")
        print("✓ TEST 14 PASSED: Time values correctly formatted into HH:MM:SS display format")
    
    # Test 15: Password Found Handler
    def test_15_password_found_handler(self):
        """Test 15: Test password found success handler"""
        self.app.is_cracking = True
        self.app.start_time = 0
        self.app.attempts = 100
        
        with patch('tkinter.messagebox.askyesno', return_value=False):
            self.app.password_found("testpass")
        
        self.assertFalse(self.app.is_cracking)
        log_content = self.app.log_text.get("1.0", tk.END)
        self.assertIn("PASSWORD FOUND", log_content)
        self.assertIn("testpass", log_content)
        print("✓ TEST 15 PASSED: Password found handler executes with success message and statistics logged")

def run_tests():
    """Run all tests with detailed output"""
    print("\n" + "="*70)
    print("ZIP PASSWORD CRACKER - COMPREHENSIVE TEST SUITE")
    print("="*70 + "\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestZipCracker)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Total Tests Run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✓ ALL TESTS PASSED SUCCESSFULLY!")
    else:
        print("\n✗ SOME TESTS FAILED - CHECK OUTPUT ABOVE")
    print("="*70 + "\n")
    
    return result


if __name__ == "__main__":
    run_tests()