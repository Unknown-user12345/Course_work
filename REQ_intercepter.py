import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
import re
from datetime import datetime

class HTTPInterceptor:
    def __init__(self):
        self.intercept_enabled = False
        self.pending_requests = []
        self.history = []
        self.proxy_running = False
        
    def start_proxy(self, host='127.0.0.1', port=8080):
        """Start the proxy server"""
        self.proxy_running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        print(f"[*] Proxy listening on {host}:{port}")
        
        while self.proxy_running:
            try:
                client_socket, addr = server.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                client_handler.daemon = True
                client_handler.start()
            except:
                break
                
    def handle_client(self, client_socket):
        """Handle incoming client connection"""
        try:
            # Receive request from browser
            request_data = client_socket.recv(4096)
            if not request_data:
                client_socket.close()
                return
                
            request_str = request_data.decode('utf-8', errors='ignore')
            
            # Parse the request
            parsed_request = self.parse_request(request_str)
            if not parsed_request:
                client_socket.close()
                return
                
            # Store in history
            history_item = {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'method': parsed_request['method'],
                'url': parsed_request['url'],
                'host': parsed_request['host'],
                'request': request_str
            }
            self.history.append(history_item)
            
            # If intercept is enabled, queue the request
            if self.intercept_enabled:
                request_item = {
                    'original': request_str,
                    'modified': request_str,
                    'socket': client_socket,
                    'host': parsed_request['host'],
                    'port': parsed_request['port'],
                    'forwarded': False
                }
                self.pending_requests.append(request_item)
            else:
                # Forward directly
                self.forward_request(request_str, parsed_request['host'], 
                                   parsed_request['port'], client_socket)
        except Exception as e:
            print(f"[!] Error handling client: {e}")
            client_socket.close()
            
    def parse_request(self, request_str):
        """Parse HTTP request to extract host and port"""
        try:
            lines = request_str.split('\n')
            first_line = lines[0]
            method, url, _ = first_line.split(' ')
            
            # Find Host header
            host = None
            port = 80
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    if ':' in host:
                        host, port = host.split(':')
                        port = int(port)
                    break
                    
            if not host:
                return None
                
            return {
                'method': method,
                'url': url,
                'host': host,
                'port': port
            }
        except:
            return None
            
    def forward_request(self, request_str, host, port, client_socket):
        """Forward the request to the target server"""
        try:
            # Connect to target server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((host, port))
            
            # Send request
            server_socket.send(request_str.encode('utf-8'))
            
            # Receive response
            response = b''
            while True:
                try:
                    chunk = server_socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    # Simple check for end of response
                    if b'\r\n\r\n' in response or len(chunk) < 4096:
                        break
                except socket.timeout:
                    break
                    
            # Send response back to client
            client_socket.send(response)
            
            server_socket.close()
            client_socket.close()
        except Exception as e:
            print(f"[!] Error forwarding request: {e}")
            client_socket.close()


class InterceptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HTTP Interceptor Proxy")
        self.root.geometry("1000x700")
        
        self.interceptor = HTTPInterceptor()
        self.current_request_index = None
        
        self.setup_ui()
        self.start_proxy_thread()
        self.update_ui()
        
    def setup_ui(self):
        """Setup the GUI components"""
        # Top control panel
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)
        
        ttk.Label(control_frame, text="Proxy: 127.0.0.1:8080", 
                 font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        self.intercept_btn = ttk.Button(control_frame, text="Intercept: OFF", 
                                       command=self.toggle_intercept)
        self.intercept_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="Clear History", 
                  command=self.clear_history).pack(side=tk.LEFT, padx=5)
        
        # Main container with notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tab 1: Interceptor
        self.intercept_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.intercept_tab, text="Interceptor")
        self.setup_interceptor_tab()
        
        # Tab 2: History
        self.history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.history_tab, text="History")
        self.setup_history_tab()
        
    def setup_interceptor_tab(self):
        """Setup the interceptor tab"""
        # Status label
        status_frame = ttk.Frame(self.intercept_tab)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = ttk.Label(status_frame, 
                                      text="Waiting for intercepted request...", 
                                      foreground="blue")
        self.status_label.pack(side=tk.LEFT)
        
        # Request editor
        ttk.Label(self.intercept_tab, text="Request:", 
                 font=('Arial', 9, 'bold')).pack(anchor=tk.W, padx=5)
        
        self.request_text = scrolledtext.ScrolledText(self.intercept_tab, 
                                                      height=20, 
                                                      font=('Courier', 9))
        self.request_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Action buttons
        btn_frame = ttk.Frame(self.intercept_tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.forward_btn = ttk.Button(btn_frame, text="Forward", 
                                     command=self.forward_request, 
                                     state=tk.DISABLED)
        self.forward_btn.pack(side=tk.LEFT, padx=5)
        
        self.drop_btn = ttk.Button(btn_frame, text="Drop", 
                                  command=self.drop_request, 
                                  state=tk.DISABLED)
        self.drop_btn.pack(side=tk.LEFT, padx=5)
        
    def setup_history_tab(self):
        """Setup the history tab"""
        # History tree
        columns = ('Time', 'Method', 'URL', 'Host')
        self.history_tree = ttk.Treeview(self.history_tab, columns=columns, 
                                        show='headings', height=15)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            
        self.history_tree.column('Time', width=80)
        self.history_tree.column('Method', width=80)
        self.history_tree.column('URL', width=300)
        self.history_tree.column('Host', width=200)
        
        self.history_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.history_tree.bind('<Double-1>', self.view_history_item)
        
        # Scrollbar for history
        scrollbar = ttk.Scrollbar(self.history_tree, orient=tk.VERTICAL, 
                                 command=self.history_tree.yview)
        self.history_tree.configure(yscroll=scrollbar.set)
        
        # Request viewer
        ttk.Label(self.history_tab, text="Request Details:", 
                 font=('Arial', 9, 'bold')).pack(anchor=tk.W, padx=5)
        
        self.history_text = scrolledtext.ScrolledText(self.history_tab, 
                                                     height=10, 
                                                     font=('Courier', 9))
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def toggle_intercept(self):
        """Toggle intercept mode"""
        self.interceptor.intercept_enabled = not self.interceptor.intercept_enabled
        
        if self.interceptor.intercept_enabled:
            self.intercept_btn.config(text="Intercept: ON")
            self.status_label.config(text="Intercept enabled - waiting for requests...", 
                                   foreground="green")
        else:
            self.intercept_btn.config(text="Intercept: OFF")
            self.status_label.config(text="Intercept disabled", 
                                   foreground="red")
            
    def forward_request(self):
        """Forward the current intercepted request"""
        if self.current_request_index is not None:
            request_item = self.interceptor.pending_requests[self.current_request_index]
            
            # Get modified request from text widget
            modified_request = self.request_text.get("1.0", tk.END).strip()
            
            # Forward the modified request
            parsed = self.interceptor.parse_request(modified_request)
            if parsed:
                threading.Thread(
                    target=self.interceptor.forward_request,
                    args=(modified_request, parsed['host'], parsed['port'], 
                          request_item['socket']),
                    daemon=True
                ).start()
                
            # Mark as forwarded and remove from pending
            request_item['forwarded'] = True
            self.interceptor.pending_requests.pop(self.current_request_index)
            self.current_request_index = None
            
            # Clear the request text
            self.request_text.delete("1.0", tk.END)
            self.forward_btn.config(state=tk.DISABLED)
            self.drop_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Request forwarded")
            
    def drop_request(self):
        """Drop the current intercepted request"""
        if self.current_request_index is not None:
            request_item = self.interceptor.pending_requests[self.current_request_index]
            
            # Close the client socket without forwarding
            try:
                request_item['socket'].close()
            except:
                pass
                
            # Remove from pending
            self.interceptor.pending_requests.pop(self.current_request_index)
            self.current_request_index = None
            
            # Clear the request text
            self.request_text.delete("1.0", tk.END)
            self.forward_btn.config(state=tk.DISABLED)
            self.drop_btn.config(state=tk.DISABLED)
            self.status_label.config(text="Request dropped")
            
    def clear_history(self):
        """Clear the history"""
        self.interceptor.history.clear()
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        self.history_text.delete("1.0", tk.END)
        
    def view_history_item(self, event):
        """View details of a history item"""
        selection = self.history_tree.selection()
        if selection:
            item_id = selection[0]
            index = self.history_tree.index(item_id)
            if index < len(self.interceptor.history):
                history_item = self.interceptor.history[index]
                self.history_text.delete("1.0", tk.END)
                self.history_text.insert("1.0", history_item['request'])
                
    def start_proxy_thread(self):
        """Start the proxy server in a separate thread"""
        proxy_thread = threading.Thread(target=self.interceptor.start_proxy, 
                                       daemon=True)
        proxy_thread.start()
        
    def update_ui(self):
        """Update UI periodically"""
        # Update history tree
        current_history_count = len(self.history_tree.get_children())
        if len(self.interceptor.history) > current_history_count:
            for item in self.interceptor.history[current_history_count:]:
                self.history_tree.insert('', tk.END, values=(
                    item['timestamp'],
                    item['method'],
                    item['url'],
                    item['host']
                ))
                
        # Check for pending requests
        if (self.interceptor.pending_requests and 
            self.current_request_index is None):
            # Show the first pending request
            self.current_request_index = 0
            request_item = self.interceptor.pending_requests[0]
            
            self.request_text.delete("1.0", tk.END)
            self.request_text.insert("1.0", request_item['modified'])
            
            self.forward_btn.config(state=tk.NORMAL)
            self.drop_btn.config(state=tk.NORMAL)
            self.status_label.config(
                text=f"Request intercepted: {request_item['host']}", 
                foreground="orange"
            )
            
        # Schedule next update
        self.root.after(100, self.update_ui)


def main():
    root = tk.Tk()
    app = InterceptorGUI(root)
    
    print("\n" + "="*60)
    print("HTTP INTERCEPTOR PROXY")
    print("="*60)
    print("\nProxy running on: 127.0.0.1:8080")
    print("\nSetup Instructions:")
    print("1. Configure your browser to use proxy:")
    print("   - HTTP Proxy: 127.0.0.1")
    print("   - Port: 8080")
    print("\n2. Toggle 'Intercept' button to capture requests")
    print("3. Edit requests and click 'Forward' or 'Drop'")
    print("\nNote: This works with HTTP only (not HTTPS)")
    print("="*60 + "\n")
    
    root.mainloop()


if __name__ == "__main__":
    main()