#!/usr/bin/env python3
"""
Advanced Steganography Tool
Supports hiding encrypted messages in images using LSB (Least Significant Bit) technique
Works on Windows and Linux
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import numpy as np
import hashlib
import secrets
import os
from pathlib import Path
import base64


class SteganographyTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Steganography Tool")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Variables
        self.input_image_path = None
        self.output_image_path = None
        self.image_preview = None
        
        # Color scheme
        self.bg_color = "#2b2b2b"
        self.fg_color = "#ffffff"
        self.accent_color = "#4a9eff"
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
            text="🔒 Advanced Steganography Tool",
            font=("Arial", 20, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Hide secret messages in images with encryption",
            font=("Arial", 10),
            bg=self.bg_color,
            fg=self.fg_color
        )
        subtitle_label.pack()
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Encode tab
        self.encode_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.encode_frame, text="Encode Message")
        self.setup_encode_tab()
        
        # Decode tab
        self.decode_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.decode_frame, text="Decode Message")
        self.setup_decode_tab()
        
        # Info tab
        self.info_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.info_frame, text="About")
        self.setup_info_tab()
    
    def setup_encode_tab(self):
        """Setup the encode message tab"""
        # Image selection
        img_frame = tk.LabelFrame(
            self.encode_frame,
            text="Select Cover Image",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        img_frame.pack(fill='x', padx=10, pady=10)
        
        btn_frame = tk.Frame(img_frame, bg=self.bg_color)
        btn_frame.pack(pady=5)
        
        self.btn_select_encode = tk.Button(
            btn_frame,
            text="Select Image",
            command=self.select_encode_image,
            bg=self.button_color,
            fg=self.fg_color,
            font=("Arial", 10),
            padx=20,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.btn_select_encode.pack(side=tk.LEFT, padx=5)
        
        self.encode_image_label = tk.Label(
            img_frame,
            text="No image selected",
            bg=self.bg_color,
            fg=self.fg_color
        )
        self.encode_image_label.pack(pady=5)
        
        # Image preview
        self.encode_preview_label = tk.Label(img_frame, bg=self.bg_color)
        self.encode_preview_label.pack(pady=5)
        
        # Message input
        msg_frame = tk.LabelFrame(
            self.encode_frame,
            text="Secret Message",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        msg_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.encode_text = scrolledtext.ScrolledText(
            msg_frame,
            height=8,
            bg="#1e1e1e",
            fg=self.fg_color,
            insertbackground=self.fg_color,
            font=("Arial", 10)
        )
        self.encode_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Password input
        pwd_frame = tk.LabelFrame(
            self.encode_frame,
            text="Encryption Password (Optional)",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        pwd_frame.pack(fill='x', padx=10, pady=10)
        
        self.encode_password_var = tk.StringVar()
        self.encode_password_entry = tk.Entry(
            pwd_frame,
            textvariable=self.encode_password_var,
            show="*",
            bg="#1e1e1e",
            fg=self.fg_color,
            insertbackground=self.fg_color,
            font=("Arial", 10)
        )
        self.encode_password_entry.pack(fill='x', padx=5, pady=5)
        
        # Encode button
        encode_btn_frame = tk.Frame(self.encode_frame, bg=self.bg_color)
        encode_btn_frame.pack(pady=10)
        
        self.btn_encode = tk.Button(
            encode_btn_frame,
            text="🔒 Encode Message",
            command=self.encode_message,
            bg=self.accent_color,
            fg=self.fg_color,
            font=("Arial", 12, "bold"),
            padx=30,
            pady=10,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.btn_encode.pack()
    
    def setup_decode_tab(self):
        """Setup the decode message tab"""
        # Image selection
        img_frame = tk.LabelFrame(
            self.decode_frame,
            text="Select Stego Image",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        img_frame.pack(fill='x', padx=10, pady=10)
        
        btn_frame = tk.Frame(img_frame, bg=self.bg_color)
        btn_frame.pack(pady=5)
        
        self.btn_select_decode = tk.Button(
            btn_frame,
            text="Select Image",
            command=self.select_decode_image,
            bg=self.button_color,
            fg=self.fg_color,
            font=("Arial", 10),
            padx=20,
            pady=5,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.btn_select_decode.pack(side=tk.LEFT, padx=5)
        
        self.decode_image_label = tk.Label(
            img_frame,
            text="No image selected",
            bg=self.bg_color,
            fg=self.fg_color
        )
        self.decode_image_label.pack(pady=5)
        
        # Image preview
        self.decode_preview_label = tk.Label(img_frame, bg=self.bg_color)
        self.decode_preview_label.pack(pady=5)
        
        # Password input
        pwd_frame = tk.LabelFrame(
            self.decode_frame,
            text="Decryption Password (if encrypted)",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        pwd_frame.pack(fill='x', padx=10, pady=10)
        
        self.decode_password_var = tk.StringVar()
        self.decode_password_entry = tk.Entry(
            pwd_frame,
            textvariable=self.decode_password_var,
            show="*",
            bg="#1e1e1e",
            fg=self.fg_color,
            insertbackground=self.fg_color,
            font=("Arial", 10)
        )
        self.decode_password_entry.pack(fill='x', padx=5, pady=5)
        
        # Decode button
        decode_btn_frame = tk.Frame(self.decode_frame, bg=self.bg_color)
        decode_btn_frame.pack(pady=10)
        
        self.btn_decode = tk.Button(
            decode_btn_frame,
            text="🔓 Decode Message",
            command=self.decode_message,
            bg=self.accent_color,
            fg=self.fg_color,
            font=("Arial", 12, "bold"),
            padx=30,
            pady=10,
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.btn_decode.pack()
        
        # Message output
        msg_frame = tk.LabelFrame(
            self.decode_frame,
            text="Decoded Message",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold")
        )
        msg_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.decode_text = scrolledtext.ScrolledText(
            msg_frame,
            height=8,
            bg="#1e1e1e",
            fg=self.fg_color,
            insertbackground=self.fg_color,
            font=("Arial", 10)
        )
        self.decode_text.pack(fill='both', expand=True, padx=5, pady=5)
    
    def setup_info_tab(self):
        """Setup the info tab"""
        info_text = """
        Advanced Steganography Tool
        ===========================
        
        This tool allows you to hide secret messages inside images using the LSB
        (Least Significant Bit) steganography technique with optional encryption.
        
        Features:
        • Hide text messages in PNG, BMP, and other lossless image formats
        • Optional password-based encryption using XOR cipher
        • Visual preview of images
        • Cross-platform support (Windows & Linux)
        • Preserves image quality while hiding data
        
        How to Use:
        
        Encoding:
        1. Select a cover image (PNG or BMP recommended)
        2. Enter your secret message
        3. Optionally add a password for encryption
        4. Click "Encode Message" and save the output image
        
        Decoding:
        1. Select the stego image containing hidden data
        2. Enter the password if the message was encrypted
        3. Click "Decode Message" to reveal the hidden text
        
        Security Notes:
        • Use lossless formats (PNG, BMP) - JPEG compression destroys hidden data
        • Longer passwords provide better encryption
        • The output image looks identical to the original
        • Maximum message size depends on image dimensions
        
        Technical Details:
        • Method: LSB (Least Significant Bit) steganography
        • Encryption: XOR cipher with SHA-256 key derivation
        • Capacity: ~1 byte per 3 pixels (RGB)
        
        Created with Python, Tkinter, and PIL
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
    
    def select_encode_image(self):
        """Select image for encoding"""
        filepath = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[
                ("Image files", "*.png *.bmp *.tiff *.tif"),
                ("All files", "*.*")
            ]
        )
        
        if filepath:
            self.input_image_path = filepath
            self.encode_image_label.config(text=os.path.basename(filepath))
            self.show_image_preview(filepath, self.encode_preview_label)
    
    def select_decode_image(self):
        """Select image for decoding"""
        filepath = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[
                ("Image files", "*.png *.bmp *.tiff *.tif"),
                ("All files", "*.*")
            ]
        )
        
        if filepath:
            self.output_image_path = filepath
            self.decode_image_label.config(text=os.path.basename(filepath))
            self.show_image_preview(filepath, self.decode_preview_label)
    
    def show_image_preview(self, filepath, label):
        """Show image preview"""
        try:
            img = Image.open(filepath)
            img.thumbnail((200, 200))
            photo = ImageTk.PhotoImage(img)
            label.config(image=photo)
            label.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image preview: {e}")
    
    def text_to_binary(self, text):
        """Convert text to binary string"""
        return ''.join(format(ord(char), '08b') for char in text)
    
    def binary_to_text(self, binary):
        """Convert binary string to text"""
        chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
        return ''.join(chr(int(char, 2)) for char in chars if len(char) == 8)
    
    def xor_encrypt_decrypt(self, data, password):
        """Simple XOR encryption/decryption"""
        if not password:
            return data
        
        # Generate key from password
        key = hashlib.sha256(password.encode()).digest()
        
        # XOR each byte
        result = bytearray()
        for i, byte in enumerate(data.encode() if isinstance(data, str) else data):
            result.append(byte ^ key[i % len(key)])
        
        return bytes(result)
    
    def encode_message(self):
        """Encode message into image"""
        if not self.input_image_path:
            messagebox.showerror("Error", "Please select a cover image first")
            return
        
        message = self.encode_text.get('1.0', tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message to hide")
            return
        
        try:
            # Open image
            img = Image.open(self.input_image_path)
            
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get image data
            img_array = np.array(img)
            height, width, channels = img_array.shape
            
            # Encrypt message if password provided
            password = self.encode_password_var.get()
            if password:
                encrypted = self.xor_encrypt_decrypt(message, password)
                message_data = base64.b64encode(encrypted).decode()
            else:
                message_data = message
            
            # Add delimiter
            message_data += "<<<END>>>"
            
            # Convert to binary
            binary_message = self.text_to_binary(message_data)
            
            # Check capacity
            max_bytes = height * width * 3 // 8
            if len(binary_message) > max_bytes * 8:
                messagebox.showerror(
                    "Error",
                    f"Message too large! Maximum size: {max_bytes} characters"
                )
                return
            
            # Encode message
            data_index = 0
            for i in range(height):
                for j in range(width):
                    for k in range(3):  # RGB channels
                        if data_index < len(binary_message):
                            # Modify LSB
                            img_array[i, j, k] = (img_array[i, j, k] & 0xFE) | int(binary_message[data_index])
                            data_index += 1
                        else:
                            break
                    if data_index >= len(binary_message):
                        break
                if data_index >= len(binary_message):
                    break
            
            # Save output image
            output_path = filedialog.asksaveasfilename(
                title="Save Stego Image",
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("BMP files", "*.bmp")]
            )
            
            if output_path:
                output_img = Image.fromarray(img_array)
                output_img.save(output_path)
                messagebox.showinfo(
                    "Success",
                    f"Message successfully encoded!\nSaved to: {output_path}"
                )
        
        except Exception as e:
            messagebox.showerror("Error", f"Encoding failed: {e}")
    
    def decode_message(self):
        """Decode message from image"""
        if not self.output_image_path:
            messagebox.showerror("Error", "Please select a stego image first")
            return
        
        try:
            # Open image
            img = Image.open(self.output_image_path)
            
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Get image data
            img_array = np.array(img)
            height, width, channels = img_array.shape
            
            # Extract binary data
            binary_message = ""
            for i in range(height):
                for j in range(width):
                    for k in range(3):
                        binary_message += str(img_array[i, j, k] & 1)
            
            # Convert to text
            message = self.binary_to_text(binary_message)
            
            # Find delimiter
            delimiter_index = message.find("<<<END>>>")
            if delimiter_index != -1:
                message = message[:delimiter_index]
            else:
                messagebox.showwarning(
                    "Warning",
                    "No valid message found or message may be corrupted"
                )
                return
            
            # Decrypt if password provided
            password = self.decode_password_var.get()
            if password:
                try:
                    encrypted = base64.b64decode(message)
                    decrypted = self.xor_encrypt_decrypt(encrypted, password)
                    message = decrypted.decode('utf-8', errors='ignore')
                except:
                    messagebox.showerror(
                        "Error",
                        "Failed to decrypt. Wrong password or message not encrypted."
                    )
                    return
            
            # Display message
            self.decode_text.delete('1.0', tk.END)
            self.decode_text.insert('1.0', message)
            
            messagebox.showinfo("Success", "Message successfully decoded!")
        
        except Exception as e:
            messagebox.showerror("Error", f"Decoding failed: {e}")


def main():
    root = tk.Tk()
    app = SteganographyTool(root)
    root.mainloop()


if __name__ == "__main__":
    main()
