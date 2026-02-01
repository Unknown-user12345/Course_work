# Advanced Steganography Tool

A powerful GUI application for hiding secret messages inside images using LSB (Least Significant Bit) steganography with optional encryption.

## Features

- 🖼️ **Image Steganography**: Hide text messages in PNG, BMP, and other lossless image formats
- 🔒 **Encryption**: Optional password-based encryption using XOR cipher with SHA-256
- 👁️ **Visual Preview**: See image previews before encoding/decoding
- 💻 **Cross-Platform**: Works on Windows and Linux
- 🎨 **Modern GUI**: Clean, dark-themed interface built with tkinter
- 📊 **Capacity Check**: Automatically calculates maximum message size

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install Pillow numpy
```

### Step 2: Run the Application

```bash
python steganography_tool.py
```

On Linux, you may need to use:

```bash
python3 steganography_tool.py
```

## Usage Guide

### Encoding a Message

1. **Select Cover Image**
   - Click "Select Image" in the Encode tab
   - Choose a PNG or BMP image (lossless formats recommended)
   - The image preview will appear

2. **Enter Secret Message**
   - Type your message in the text area
   - Can be any length (within capacity limits)

3. **Add Password (Optional)**
   - Enter a password for encryption
   - Leave blank for no encryption

4. **Encode**
   - Click "🔒 Encode Message"
   - Choose where to save the output image
   - The output looks identical to the original!

### Decoding a Message

1. **Select Stego Image**
   - Click "Select Image" in the Decode tab
   - Choose the image containing hidden data

2. **Enter Password (If Used)**
   - Enter the same password used during encoding
   - Leave blank if no encryption was used

3. **Decode**
   - Click "🔓 Decode Message"
   - The hidden message will appear in the text area

## Technical Details

### How It Works

**LSB Steganography**: The tool modifies the least significant bit of each pixel's RGB values. Since changing the LSB only alters the pixel value by ±1, the changes are imperceptible to the human eye.

**Encryption**: When a password is provided:
1. The password is hashed using SHA-256
2. The message is XOR-encrypted with the hash
3. The encrypted data is base64-encoded before hiding

**Capacity**: The maximum message size depends on image dimensions:
- Formula: `(width × height × 3) / 8` bytes
- Example: A 1920×1080 image can hide ~777 KB of text

### Supported Formats

**Recommended (Lossless)**:
- PNG (best choice)
- BMP
- TIFF

**Not Recommended**:
- JPEG (lossy compression destroys hidden data)
- GIF (limited colors)

## Security Considerations

⚠️ **Important Notes**:

1. **Format Matters**: Always use lossless formats (PNG, BMP). JPEG compression will destroy the hidden message.

2. **Password Strength**: Use strong passwords for encryption. The XOR cipher is simple but effective when combined with a good password.

3. **Stealth**: The output image is visually identical to the input, but:
   - Statistical analysis can detect LSB steganography
   - This is for privacy, not high-security applications

4. **Backup**: Keep a copy of the original image and remember your password!

## Example Workflow

```bash
# 1. Start the application
python steganography_tool.py

# 2. Encode a message
- Select: vacation_photo.png
- Message: "Meeting at the usual place, 3 PM"
- Password: "SecurePass123"
- Save as: vacation_photo_stego.png

# 3. Share the stego image
# Send vacation_photo_stego.png via email, messaging, etc.

# 4. Decode the message
- Select: vacation_photo_stego.png
- Password: "SecurePass123"
- Decoded: "Meeting at the usual place, 3 PM"
```

## Troubleshooting

### "Message too large" error
- Use a larger image
- Compress your message
- Split into multiple images

### "No valid message found"
- Ensure you're using the correct stego image
- Check if the image was compressed (JPEG)
- Verify the image wasn't modified

### "Failed to decrypt"
- Check if password is correct
- Ensure message was actually encrypted
- Try decoding without password

### Display issues on Linux
- Install tkinter: `sudo apt-get install python3-tk`
- Install imaging libraries: `sudo apt-get install python3-pil python3-pil.imagetk`

## Advanced Tips

1. **Multiple Messages**: You can encode multiple messages in different regions by modifying the code

2. **File Compression**: Compress large text files before encoding to save space

3. **Batch Processing**: Modify the script to process multiple images

4. **Custom Encryption**: Replace XOR with AES for stronger encryption

## Limitations

- Maximum message size depends on image dimensions
- Works best with lossless image formats
- Not suitable for high-security military/government use
- Can be detected by steganalysis tools

## License

Free to use and modify for personal and educational purposes.

## Credits

Built with:
- Python 3
- Tkinter (GUI)
- Pillow (Image processing)
- NumPy (Array operations)

## Contributing

Feel free to fork, modify, and improve this tool!

## Disclaimer

This tool is for educational and privacy purposes only. Users are responsible for complying with local laws regarding encryption and data privacy.
