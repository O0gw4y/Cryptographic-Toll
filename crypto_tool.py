import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import hashlib
import os
from tkinter import font as tkFont

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptographic Tool")
        self.root.geometry("800x600")  # Larger default size
        self.root.resizable(True, True)
        
        # Set theme colors - modern dark theme
        self.bg_color = "#1e272e"
        self.fg_color = "#ecf0f1"
        self.accent_color = "#3498db"
        self.button_color = "#0984e3"
        self.secondary_bg = "#2d3436"
        self.success_color = "#00b894"
        
        # Custom fonts
        self.title_font = tkFont.Font(family="Helvetica", size=20, weight="bold")
        self.header_font = tkFont.Font(family="Helvetica", size=12, weight="bold")
        self.text_font = tkFont.Font(family="Helvetica", size=10)
        
        self.root.configure(bg=self.bg_color)
        
        # Configure row and column weights for the root window
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = tk.Frame(self.root, bg=self.bg_color, padx=20, pady=20)
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure main_frame to expand with window
        main_frame.grid_rowconfigure(0, weight=0)  # Title row
        main_frame.grid_rowconfigure(1, weight=0)  # Technique frame
        main_frame.grid_rowconfigure(2, weight=0)  # Shift frame (when visible)
        main_frame.grid_rowconfigure(3, weight=0)  # Operation frame
        main_frame.grid_rowconfigure(4, weight=0)  # File frame (when visible)
        main_frame.grid_rowconfigure(5, weight=1)  # Input frame
        main_frame.grid_rowconfigure(6, weight=0)  # Button frame
        main_frame.grid_rowconfigure(7, weight=1)  # Output frame
        main_frame.grid_rowconfigure(8, weight=0)  # Status bar
        main_frame.grid_columnconfigure(0, weight=1)  # All columns expand
        
        # Title with icon
        title_frame = tk.Frame(main_frame, bg=self.bg_color)
        title_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        title_frame.grid_columnconfigure(1, weight=1)  # Make title expand
        
        # Add a lock icon using text symbol (can be replaced with an image)
        icon_label = tk.Label(title_frame, text="🔒", font=("Helvetica", 24), 
                             bg=self.bg_color, fg=self.accent_color)
        icon_label.grid(row=0, column=0, padx=(0, 10))
        
        title_label = tk.Label(title_frame, text="Cryptographic Tool", 
                              font=self.title_font, 
                              bg=self.bg_color, fg=self.fg_color)
        title_label.grid(row=0, column=1, sticky="w")
        
        # Encryption technique selection - with styled frame
        technique_frame = tk.Frame(main_frame, bg=self.secondary_bg, padx=15, pady=10, bd=1, relief=tk.GROOVE)
        technique_frame.grid(row=1, column=0, sticky="ew", pady=10)
        technique_frame.grid_columnconfigure(1, weight=1)  # Make the combobox area expandable
        
        technique_label = tk.Label(technique_frame, text="Select Encryption Technique:", 
                                  font=self.header_font,
                                  bg=self.secondary_bg, fg=self.fg_color)
        technique_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
        
        self.technique_var = tk.StringVar()
        self.techniques = ["Caesar Cipher", "ROT13", "Atbash", "MD5 Hash"]
        self.technique_var.set(self.techniques[0])
        
        # Configure the combobox style
        combo_style = ttk.Style()
        combo_style.theme_use('clam')
        combo_style.configure('TCombobox', fieldbackground=self.fg_color, background=self.accent_color)
        
        technique_menu = ttk.Combobox(technique_frame, textvariable=self.technique_var, 
                                     values=self.techniques, state="readonly", width=15, font=self.text_font)
        technique_menu.grid(row=0, column=1, sticky="w")
        
        # Caesar cipher shift input (only visible when Caesar Cipher is selected)
        self.shift_frame = tk.Frame(main_frame, bg=self.secondary_bg, padx=15, pady=10, bd=1, relief=tk.GROOVE)
        # Don't grid here, will be placed in update_ui
        self.shift_frame.grid_columnconfigure(1, weight=1)  # Make the entry area expandable
        
        shift_label = tk.Label(self.shift_frame, text="Shift Value (1-25):", 
                              font=self.header_font,
                              bg=self.secondary_bg, fg=self.fg_color)
        shift_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
        
        self.shift_var = tk.StringVar()
        self.shift_var.set("3")
        
        # Create a validation command for the entry
        vcmd = (self.root.register(self.validate_shift), '%P')
        
        self.shift_entry = tk.Entry(self.shift_frame, textvariable=self.shift_var, width=5, 
                              font=self.text_font, bg=self.fg_color, fg=self.bg_color,
                              validate='key', validatecommand=vcmd)
        self.shift_entry.grid(row=0, column=1, sticky="w")
        
        # Operation selection with styled frame
        self.operation_frame = tk.Frame(main_frame, bg=self.secondary_bg, padx=15, pady=10, bd=1, relief=tk.GROOVE)
        self.operation_frame.grid(row=3, column=0, sticky="ew", pady=10)
        self.operation_frame.grid_columnconfigure(3, weight=1)  # Make the frame expandable
        
        operation_label = tk.Label(self.operation_frame, text="Operation:", 
                                  font=self.header_font,
                                  bg=self.secondary_bg, fg=self.fg_color)
        operation_label.grid(row=0, column=0, padx=(0, 15), sticky="w")
        
        self.operation_var = tk.StringVar()
        self.operation_var.set("encrypt")
        
        # Custom radio button style
        encrypt_radio = tk.Radiobutton(self.operation_frame, text="Encrypt", variable=self.operation_var, 
                                     value="encrypt", bg=self.secondary_bg, fg=self.fg_color, 
                                     selectcolor=self.secondary_bg, activebackground=self.secondary_bg,
                                     font=self.text_font, indicatoron=0, width=8,
                                     highlightbackground=self.accent_color, highlightthickness=1)
        encrypt_radio.grid(row=0, column=1, padx=(0, 10), sticky="w")
        
        decrypt_radio = tk.Radiobutton(self.operation_frame, text="Decrypt", variable=self.operation_var, 
                                     value="decrypt", bg=self.secondary_bg, fg=self.fg_color, 
                                     selectcolor=self.secondary_bg, activebackground=self.secondary_bg,
                                     font=self.text_font, indicatoron=0, width=8,
                                     highlightbackground=self.accent_color, highlightthickness=1)
        decrypt_radio.grid(row=0, column=2, sticky="w")
        
        # File upload frame (only visible for MD5 Hash)
        self.file_frame = tk.Frame(main_frame, bg=self.secondary_bg, padx=15, pady=10, bd=1, relief=tk.GROOVE)
        # Will be placed in update_ui
        self.file_frame.grid_columnconfigure(1, weight=1)  # Make the file path area expandable
        
        self.file_path_var = tk.StringVar()
        self.file_path_var.set("No file selected")
        
        file_label = tk.Label(self.file_frame, text="File:", 
                             font=self.header_font,
                             bg=self.secondary_bg, fg=self.fg_color)
        file_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
        
        file_path_label = tk.Label(self.file_frame, textvariable=self.file_path_var, 
                                  bg=self.secondary_bg, fg=self.accent_color, anchor="w",
                                  font=self.text_font)
        file_path_label.grid(row=0, column=1, padx=(0, 10), sticky="ew")
        
        browse_button = tk.Button(self.file_frame, text="Browse", command=self.browse_file, 
                                bg=self.button_color, fg=self.fg_color, 
                                activebackground=self.accent_color, 
                                activeforeground=self.fg_color,
                                font=self.text_font, padx=10, pady=2,
                                relief=tk.RAISED, bd=2)
        browse_button.grid(row=0, column=2, sticky="e")
        
        # Initially hide the file frame - will be shown when MD5 is selected
        # Will be placed in update_ui
        
        # Input text with styled frame
        input_frame = tk.Frame(main_frame, bg=self.secondary_bg, padx=15, pady=10, bd=1, relief=tk.GROOVE)
        input_frame.grid(row=5, column=0, sticky="nsew", pady=10)
        input_frame.grid_rowconfigure(1, weight=1)  # Make the text area expandable vertically
        input_frame.grid_columnconfigure(0, weight=1)  # Make the text area expandable horizontally
        
        input_label = tk.Label(input_frame, text="Input Text:", 
                              font=self.header_font,
                              bg=self.secondary_bg, fg=self.fg_color)
        input_label.grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        self.input_text = scrolledtext.ScrolledText(input_frame, height=5, width=50, wrap=tk.WORD,
                                                  font=self.text_font, bg=self.fg_color, fg=self.bg_color,
                                                  insertbackground=self.accent_color)
        self.input_text.grid(row=1, column=0, sticky="nsew")
        
        # Process and Clear buttons with improved styling
        button_frame = tk.Frame(main_frame, bg=self.bg_color)
        button_frame.grid(row=6, column=0, sticky="ew", pady=10)
        button_frame.grid_columnconfigure(0, weight=1)  # Center the buttons
        
        # Create a container for buttons to center them
        button_container = tk.Frame(button_frame, bg=self.bg_color)
        button_container.grid(row=0, column=0)
        
        self.process_button = tk.Button(button_container, text="Process", command=self.process_text, 
                                 bg=self.button_color, fg=self.fg_color, 
                                 activebackground=self.accent_color, 
                                 activeforeground=self.fg_color, 
                                 font=self.header_font,
                                 padx=30, pady=8, bd=0,
                                 cursor="hand2")
        self.process_button.grid(row=0, column=0, padx=5)
        
        self.clear_button = tk.Button(button_container, text="Clear", command=self.clear_fields, 
                               bg=self.secondary_bg, fg=self.fg_color, 
                               activebackground=self.accent_color, 
                               activeforeground=self.fg_color, 
                               font=self.header_font,
                               padx=30, pady=8, bd=0,
                               cursor="hand2")
        self.clear_button.grid(row=0, column=1, padx=5)
        
        # Add hover effects to the buttons
        self.process_button.bind("<Enter>", lambda e: self.process_button.config(bg=self.accent_color))
        self.process_button.bind("<Leave>", lambda e: self.process_button.config(bg=self.button_color))
        
        self.clear_button.bind("<Enter>", lambda e: self.clear_button.config(bg=self.accent_color))
        self.clear_button.bind("<Leave>", lambda e: self.clear_button.config(bg=self.secondary_bg))
        
        # Add keyboard shortcuts
        self.root.bind("<F5>", lambda event: self.process_text())
        self.root.bind("<Escape>", lambda event: self.clear_fields())
        
        # Output text with styled frame
        output_frame = tk.Frame(main_frame, bg=self.secondary_bg, padx=15, pady=10, bd=1, relief=tk.GROOVE)
        output_frame.grid(row=7, column=0, sticky="nsew", pady=10)
        output_frame.grid_rowconfigure(1, weight=1)  # Make the text area expandable vertically
        output_frame.grid_columnconfigure(0, weight=1)  # Make the text area expandable horizontally
        
        # Output header with copy button
        output_header = tk.Frame(output_frame, bg=self.secondary_bg)
        output_header.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        output_header.grid_columnconfigure(0, weight=1)  # Make label expand
        
        output_label = tk.Label(output_header, text="Output Text:", 
                               font=self.header_font,
                               bg=self.secondary_bg, fg=self.fg_color)
        output_label.grid(row=0, column=0, sticky="w")
        
        # Add copy button
        copy_button = tk.Button(output_header, text="Copy", command=self.copy_output, 
                              bg=self.button_color, fg=self.fg_color, 
                              activebackground=self.accent_color, 
                              activeforeground=self.fg_color,
                              font=self.text_font, padx=10, pady=0,
                              relief=tk.RAISED, bd=1, cursor="hand2")
        copy_button.grid(row=0, column=1, sticky="e")
        
        # Add hover effect to the copy button
        copy_button.bind("<Enter>", lambda e: copy_button.config(bg=self.accent_color))
        copy_button.bind("<Leave>", lambda e: copy_button.config(bg=self.button_color))
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=5, width=50, wrap=tk.WORD,
                                                   font=self.text_font, bg=self.fg_color, fg=self.bg_color)
        self.output_text.grid(row=1, column=0, sticky="nsew")
        
        # Add a status bar at the bottom
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_bar = tk.Label(main_frame, textvariable=self.status_var, 
                             bg=self.bg_color, fg=self.accent_color, 
                             font=("Helvetica", 8), anchor=tk.W, bd=1, relief=tk.SUNKEN)
        status_bar.grid(row=8, column=0, sticky="ew")
        
        # Bind technique selection to update UI
        technique_menu.bind("<<ComboboxSelected>>", self.update_ui)
        
        # Initial UI update
        self.update_ui()
    
    def update_ui(self, event=None):
        # Show/hide shift input based on selected technique
        selected_technique = self.technique_var.get()
        
        print(f"update_ui called with technique: {selected_technique}")
        
        # First, hide all optional frames
        self.shift_frame.grid_remove()
        self.file_frame.grid_remove()
        
        # Then show the appropriate frames based on the selected technique
        if selected_technique == "Caesar Cipher":
            print("Showing shift frame for Caesar Cipher")
            self.shift_frame.grid(row=4, column=0, sticky="ew", pady=10)
        
        # Show file upload frame for MD5 Hash
        if selected_technique == "MD5 Hash":
            print("Showing file frame for MD5 Hash")
            self.file_frame.grid(row=4, column=0, sticky="ew", pady=10)
            
        # Force update to ensure changes are visible
        self.root.update()
        
        # Enable/disable decrypt option based on selected technique
        if selected_technique == "MD5 Hash":
            # MD5 is one-way, can't decrypt
            self.operation_var.set("encrypt")
            for widget in self.operation_frame.winfo_children():
                if isinstance(widget, tk.Radiobutton) and widget.cget("text") == "Decrypt":
                    widget.config(state=tk.DISABLED)
        else:
            for widget in self.operation_frame.winfo_children():
                if isinstance(widget, tk.Radiobutton) and widget.cget("text") == "Decrypt":
                    widget.config(state=tk.NORMAL)
                    
        # Force update the UI to ensure changes are visible
        self.root.update()
    
    def validate_shift(self, new_value):
        # Allow empty string or digits between 1-25
        if new_value == "" or (new_value.isdigit() and 1 <= int(new_value) <= 25):
            return True
        return False
    
    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            # Truncate the file path if it's too long
            display_path = file_path
            if len(display_path) > 30:
                display_path = "..." + display_path[-27:]
            self.file_path_var.set(display_path)
            self.file_path = file_path
            self.status_var.set(f"File selected: {os.path.basename(file_path)}")
        else:
            self.file_path_var.set("No file selected")
            self.file_path = None
    
    def process_text(self):
        try:
            technique = self.technique_var.get()
            operation = self.operation_var.get()
            
            # Update status bar
            self.status_var.set(f"Processing {technique}...")
            self.root.update()
            
            print(f"Processing with technique: {technique}, operation: {operation}")
            
            # Change button color to indicate processing
            self.process_button.config(bg=self.success_color)
            self.root.update()
            
            # For MD5 Hash with file upload
            if technique == "MD5 Hash" and hasattr(self, 'file_path') and self.file_path:
                try:
                    result = self.md5_hash_file(self.file_path)
                    self.output_text.delete("1.0", tk.END)
                    self.output_text.insert(tk.END, result)
                    self.status_var.set(f"MD5 hash of file {os.path.basename(self.file_path)} calculated successfully")
                    # Reset button color
                    self.process_button.config(bg=self.button_color)
                    return
                except Exception as e:
                    self.output_text.delete("1.0", tk.END)
                    self.output_text.insert(tk.END, f"Error processing file: {str(e)}")
                    self.status_var.set("Error processing file")
                    # Reset button color
                    self.process_button.config(bg=self.button_color)
                    return
        
            # For text input
            input_text = self.input_text.get("1.0", tk.END).strip()
            
            if not input_text:
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, "Please enter some text to process.")
                self.status_var.set("No input text provided")
                # Reset button color
                self.process_button.config(bg=self.button_color)
                return
            
            result = ""
        
            if technique == "Caesar Cipher":
                try:
                    shift_value = self.shift_var.get()
                    print(f"Shift value: '{shift_value}'")
                    
                    if not shift_value.strip():
                        self.output_text.delete("1.0", tk.END)
                        self.output_text.insert(tk.END, "Please enter a shift value.")
                        self.status_var.set("No shift value provided")
                        # Reset button color
                        self.process_button.config(bg=self.button_color)
                        return
                        
                    shift = int(shift_value)
                    if shift < 1 or shift > 25:
                        self.output_text.delete("1.0", tk.END)
                        self.output_text.insert(tk.END, "Shift value must be between 1 and 25.")
                        self.status_var.set("Invalid shift value")
                        # Reset button color
                        self.process_button.config(bg=self.button_color)
                        return
                    
                    if operation == "decrypt":
                        shift = -shift
                    
                    result = self.caesar_cipher(input_text, shift)
                    print(f"Caesar cipher result: '{result}'")
                    operation_text = "encrypted" if operation == "encrypt" else "decrypted"
                    self.status_var.set(f"Text {operation_text} with Caesar Cipher (shift={abs(shift)})")
                except ValueError as e:
                    print(f"ValueError in Caesar cipher: {e}")
                    self.output_text.delete("1.0", tk.END)
                    self.output_text.insert(tk.END, "Invalid shift value. Please enter a number.")
                    self.status_var.set("Invalid shift value")
                    # Reset button color
                    self.process_button.config(bg=self.button_color)
                    return
        
            elif technique == "ROT13":
                result = self.rot13(input_text)
                operation_text = "encrypted" if operation == "encrypt" else "decrypted"
                self.status_var.set(f"Text {operation_text} with ROT13")
            
            elif technique == "Atbash":
                result = self.atbash(input_text)
                operation_text = "encrypted" if operation == "encrypt" else "decrypted"
                self.status_var.set(f"Text {operation_text} with Atbash cipher")
            
            elif technique == "MD5 Hash":
                result = self.md5_hash(input_text)
                self.status_var.set("MD5 hash calculated successfully")
            
            print(f"Final result: '{result}'")
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
            print(f"Text inserted into output_text")
            
            # Reset button color
            self.process_button.config(bg=self.button_color)
        except Exception as e:
            print(f"Error in process_text: {e}")
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, f"An error occurred: {str(e)}")
            self.status_var.set("Error during processing")
            # Reset button color
            self.process_button.config(bg=self.button_color)
    
    def caesar_cipher(self, text, shift):
        result = ""
        
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                # Convert to 0-25, shift, and convert back to ASCII
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        
        return result
    
    def rot13(self, text):
        # ROT13 is just a Caesar cipher with shift 13
        return self.caesar_cipher(text, 13)
    
    def atbash(self, text):
        result = ""
        
        for char in text:
            if char.isalpha():
                if char.islower():
                    # Map 'a' to 'z', 'b' to 'y', etc.
                    result += chr(219 - ord(char))  # 219 = ord('a') + ord('z')
                else:
                    # Map 'A' to 'Z', 'B' to 'Y', etc.
                    result += chr(155 - ord(char))  # 155 = ord('A') + ord('Z')
            else:
                result += char
        
        return result
    
    def md5_hash(self, text):
        # MD5 is one-way, so we only support encryption
        return hashlib.md5(text.encode()).hexdigest()
    
    def md5_hash_file(self, file_path):
        # Calculate MD5 hash of a file
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
        
    def copy_output(self):
        # Copy output text to clipboard
        output_text = self.output_text.get("1.0", tk.END).strip()
        if output_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(output_text)
            self.status_var.set("Output copied to clipboard")
        else:
            self.status_var.set("No output to copy")
            
    def clear_fields(self):
        # Clear input and output fields
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        
        # Reset file selection if MD5 is selected
        if self.technique_var.get() == "MD5 Hash":
            self.file_path_var.set("No file selected")
            self.file_path = None
            
        # Reset status bar
        self.status_var.set("Fields cleared")
        
        # Set focus to input text
        self.input_text.focus_set()


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()