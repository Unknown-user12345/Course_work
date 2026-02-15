# HTTP Interceptor Proxy

A Burp Suite-style HTTP intercepting proxy built from scratch in Python with a GUI.

## Features

- ✅ Intercept HTTP requests in real-time
- ✅ Edit requests before forwarding
- ✅ View request history
- ✅ Forward or drop intercepted requests
- ✅ Clean, usable GUI

## Requirements

```bash
pip install tkinter  # Usually comes with Python
```

## How to Use

### 1. Run the Proxy

```bash
python http_interceptor.py
```

### 2. Configure Your Browser

**Firefox:**
- Settings → Network Settings → Manual proxy configuration
- HTTP Proxy: `127.0.0.1`
- Port: `8080`
- Check "Use this proxy server for all protocols"

**Chrome:**
- Use a proxy extension like "Proxy SwitchyOmega"
- Or run: `chrome.exe --proxy-server="127.0.0.1:8080"`

### 3. Use the Tool

1. **Intercept Mode:** Click "Intercept: OFF" to turn it ON
2. **Browse:** Visit HTTP websites (not HTTPS)
3. **Edit Requests:** Modify headers, parameters, or body
4. **Forward/Drop:** Click "Forward" to send or "Drop" to block

### 4. View History

- Switch to "History" tab to see all requests
- Double-click any request to view details

## Important Notes

⚠️ **HTTP Only:** This proxy works with HTTP traffic only, not HTTPS (SSL/TLS encrypted traffic would require certificate handling)

⚠️ **Educational Use:** This is for learning and testing on your own systems only

⚠️ **Testing Sites:** Use `http://example.com` or `http://httpbin.org` for testing

## Example Use Cases

- Test web application behavior with modified requests
- Debug HTTP traffic
- Learn how HTTP requests work
- Practice web security concepts

## Tabs Explained

### Interceptor Tab
- Shows intercepted requests when intercept is ON
- Edit the request in the text box
- Click "Forward" to send (with your modifications)
- Click "Drop" to block the request

### History Tab
- Shows all requests that passed through the proxy
- Double-click to view request details
- Click "Clear History" to reset

## Tips

- Start with intercept OFF to build history
- Turn intercept ON only when you want to modify a specific request
- The status bar shows what's happening in real-time

## Troubleshooting

**No requests appearing?**
- Make sure your browser proxy is set correctly
- Visit HTTP sites (not HTTPS)
- Check the console for error messages

**Requests hanging?**
- The proxy might be in intercept mode - check the button
- Click "Drop" or "Forward" on pending requests