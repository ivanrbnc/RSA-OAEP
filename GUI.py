import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from RSAOAEP import RSAOAEP

class GUI:
    def __init__(self, root):
        '''Initialization'''
        self.root = root
        self.root.title("RSA-OAEP Encryption Tool")
        self.root.geometry("300x550")
        
        # Center the main window
        self.center_window(self.root)
        
        self.create_widgets()
    
    def center_window(self, window):
        '''Center a window on the screen'''
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
    def browse_file(self, entry_widget):
        '''Open file window and update entry widget'''
        filename = filedialog.askopenfilename()
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

    def save_file_dialog(self, default_ext, filetypes, title):
        '''Open save file window and return filename'''
        return filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=filetypes,
            title=title
        )

    def show_key_generation_dialog(self):
        '''Open a dialog to configure key generation'''
        # Create a dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate RSA Key Pair")
        dialog.geometry("450x180")
        dialog.transient(self.root)
        dialog.grab_set()  # Make window modal
        
        # Center the dialog
        self.center_window(dialog)
        
        # Main frame
        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Private key filename
        ttk.Label(main_frame, text="Private Key Filename:").grid(row=0, column=0, sticky=tk.W, pady=5)
        priv_var = tk.StringVar(value="private_key.txt")
        ttk.Entry(main_frame, textvariable=priv_var, width=30).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        
        # Public key filename
        ttk.Label(main_frame, text="Public Key Filename:").grid(row=1, column=0, sticky=tk.W, pady=5)
        pub_var = tk.StringVar(value="public_key.txt")
        ttk.Entry(main_frame, textvariable=pub_var, width=30).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        
        # Output directory
        ttk.Label(main_frame, text="Save Location:").grid(row=2, column=0, sticky=tk.W, pady=5)
        dir_var = tk.StringVar()
        dir_entry = ttk.Entry(main_frame, textvariable=dir_var, width=30)
        dir_entry.grid(row=2, column=1, sticky=tk.EW, padx=5, pady=5)
        
        def browse_dir():
            directory = filedialog.askdirectory(title="Select Folder to Save Keys")
            if directory:
                # Replace backslashes with forward slashes
                directory = directory.replace('\\', '/')
                dir_var.set(directory)
        
        ttk.Button(main_frame, text="Browse", command=browse_dir).grid(row=2, column=2, padx=5, pady=5)
        
        # Configure grid
        main_frame.columnconfigure(1, weight=1)
        
        # Button frame
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        result = {"success": False, "pub_filename": "", "priv_filename": ""}
        
        def on_generate():
            if not priv_var.get() or not pub_var.get() or not dir_var.get():
                messagebox.showerror("Error", "Please provide filenames and select a save location")
                return
            
            # Construct full paths with forward slashes
            directory = dir_var.get()
            if not directory.endswith('/'):
                directory += '/'
                
            result["success"] = True
            result["pub_filename"] = directory + pub_var.get()
            result["priv_filename"] = directory + priv_var.get()
            dialog.destroy()
        
        def on_cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Generate Keys", command=on_generate).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=5)
        
        # Wait for the dialog to close
        self.root.wait_window(dialog)
        
        return result
    
    def generate_keys(self):
        '''Generate RSA key pair (2048-bit)'''
        # Show dialog to get filenames
        result = self.show_key_generation_dialog()
        
        if not result["success"]:
            self.status_label.config(text="Key generation cancelled")
            return
        
        try:
            # Create a progress dialog
            progress_dialog = tk.Toplevel(self.root)
            progress_dialog.title("Generating Keys")
            progress_dialog.geometry("300x100")
            progress_dialog.transient(self.root)
            progress_dialog.grab_set()
            
            # Center the progress dialog
            self.center_window(progress_dialog)
            
            # Add progress message
            message_label = ttk.Label(
                progress_dialog, 
                text="Generating 2048-bit RSA keys...\nThis may take a moment.",
                font=("Arial", 10, "bold"),
                justify=tk.CENTER
            )
            message_label.pack(pady=30)
            
            # Update status in main window
            self.status_label.config(text="Generating 2048-bit keys...")
            self.root.update()
            
            # Normalize path separators for consistency
            pub_filename = result["pub_filename"].replace('\\', '/')
            priv_filename = result["priv_filename"].replace('\\', '/')
            
            # Start a background process to generate keys
            def generate_key_task():
                try:
                    # Generate 2048-bit RSA key pair
                    key_size = 2048
                    n, e, d = RSAOAEP.generate_rsa_keys(key_size)
                    
                    # Saving public key
                    with open(pub_filename, 'w') as f:
                        f.write(f"n={hex(n)}\n")
                        f.write(f"e={hex(e)}\n")
                    
                    # Saving private key
                    with open(priv_filename, 'w') as f:
                        f.write(f"n={hex(n)}\n")
                        f.write(f"d={hex(d)}\n")
                    
                    # Close progress dialog
                    progress_dialog.destroy()
                    
                    # Show success message
                    self.status_label.config(text="Key pair generated successfully")
                    messagebox.showinfo("Success", "RSA key pair generated and saved successfully:\n\n"
                                      f"Public Key: {pub_filename}\n"
                                      f"Private Key: {priv_filename}")
                    
                except Exception as e:
                    progress_dialog.destroy()
                    self.status_label.config(text=f"Error: {str(e)}")
                    messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")
            
            # Start the key generation in a separate thread
            self.root.after(100, generate_key_task)
            
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to prepare key generation: {str(e)}")

    def encrypt_file(self):
        '''Encrypt file using RSA-OAEP'''
        pub_key_file = self.pub_key_entry.get()
        plain_file = self.plain_file_entry.get()
        
        if not pub_key_file or not plain_file:
            messagebox.showerror("Error", "Please select both public key file and file to encrypt")
            return
        
        try:
            # Get output filename
            cipher_filename = self.save_file_dialog(
                ".enc",
                [("Encrypted Files", "*.enc")],
                "Save Encrypted File As"
            )
            
            if not cipher_filename:
                self.status_label.config(text="Encryption cancelled")
                return
                
            # Create a progress dialog
            progress_dialog = tk.Toplevel(self.root)
            progress_dialog.title("Encrypting File")
            progress_dialog.geometry("300x100")
            progress_dialog.transient(self.root)
            progress_dialog.grab_set()
            
            # Center the progress dialog
            self.center_window(progress_dialog)
            
            # Add progress message
            message_label = ttk.Label(
                progress_dialog, 
                text="Encrypting file...\nThis may take a moment.",
                font=("Arial", 10, "bold"),
                justify=tk.CENTER
            )
            message_label.pack(pady=30)
            
            # Update status in main window
            self.status_label.config(text="Encrypting file...")
            self.root.update()
            
            # Process paths
            pub_key_file = pub_key_file.replace('\\', '/')
            plain_file = plain_file.replace('\\', '/')
            cipher_filename = cipher_filename.replace('\\', '/')
            
            # Start a background process to encrypt
            def encrypt_task():
                try:
                    # Perform RSA-OAEP encryption
                    RSAOAEP.encrypt_file(plain_file, cipher_filename, pub_key_file)
                    
                    # Close progress dialog
                    progress_dialog.destroy()
                    
                    # Show success message
                    self.status_label.config(text="File encrypted successfully")
                    messagebox.showinfo("Success", "File encrypted successfully")
                    
                except Exception as e:
                    progress_dialog.destroy()
                    self.status_label.config(text=f"Error: {str(e)}")
                    messagebox.showerror("Error", f"Failed to encrypt file: {str(e)}")
            
            # Start the encryption in a separate thread
            self.root.after(100, encrypt_task)
            
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to prepare encryption: {str(e)}")

    def decrypt_file(self):
        '''Decrypt file using RSA-OAEP'''
        priv_key_file = self.priv_key_entry.get()
        cipher_file = self.cipher_file_entry.get()
        
        if not priv_key_file or not cipher_file:
            messagebox.showerror("Error", "Please select both private key file and file to decrypt")
            return
        
        try:
            # Get output filename
            plain_filename = self.save_file_dialog(
                ".bin",
                [("All Files", "*.*")],
                "Save Decrypted File As"
            )
            
            if not plain_filename:
                self.status_label.config(text="Decryption cancelled")
                return
                
            # Create a progress dialog
            progress_dialog = tk.Toplevel(self.root)
            progress_dialog.title("Decrypting File")
            progress_dialog.geometry("300x100")
            progress_dialog.transient(self.root)
            progress_dialog.grab_set()
            
            # Center the progress dialog
            self.center_window(progress_dialog)
            
            # Add progress message
            message_label = ttk.Label(
                progress_dialog, 
                text="Decrypting file...\nThis may take a moment.",
                font=("Arial", 10, "bold"),
                justify=tk.CENTER
            )
            message_label.pack(pady=30)
            
            # Update status in main window
            self.status_label.config(text="Decrypting file...")
            self.root.update()
            
            # Process paths
            priv_key_file = priv_key_file.replace('\\', '/')
            cipher_file = cipher_file.replace('\\', '/')
            plain_filename = plain_filename.replace('\\', '/')
            
            # Start a background process to decrypt
            def decrypt_task():
                try:
                    # Perform RSA-OAEP decryption
                    RSAOAEP.decrypt_file(cipher_file, plain_filename, priv_key_file)
                    
                    # Close progress dialog
                    progress_dialog.destroy()
                    
                    # Show success message
                    self.status_label.config(text="File decrypted successfully")
                    messagebox.showinfo("Success", "File decrypted successfully")
                    
                except Exception as e:
                    progress_dialog.destroy()
                    self.status_label.config(text=f"Error: {str(e)}")
                    messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")
            
            # Start the decryption in a separate thread
            self.root.after(100, decrypt_task)
            
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to prepare decryption: {str(e)}")

    def create_widgets(self):
        '''Widgets for every functionalities'''
        # Key Generation Frame
        key_frame = ttk.LabelFrame(self.root, text="Key Generation", padding="10")
        key_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(key_frame, text="Generate Key Pair (2048-bit)", command=self.generate_keys).pack(fill=tk.X)

        # Encryption Frame
        enc_frame = ttk.LabelFrame(self.root, text="Encryption", padding="10")
        enc_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(enc_frame, text="Public Key File:").pack(anchor=tk.W)
        self.pub_key_entry = ttk.Entry(enc_frame)
        self.pub_key_entry.pack(fill=tk.X, pady=2)
        ttk.Button(enc_frame, text="Browse", command=lambda: self.browse_file(self.pub_key_entry)).pack(anchor=tk.E)

        ttk.Label(enc_frame, text="File to Encrypt:").pack(anchor=tk.W)
        self.plain_file_entry = ttk.Entry(enc_frame)
        self.plain_file_entry.pack(fill=tk.X, pady=2)
        ttk.Button(enc_frame, text="Browse", command=lambda: self.browse_file(self.plain_file_entry)).pack(anchor=tk.E)

        ttk.Button(enc_frame, text="Encrypt File", command=self.encrypt_file).pack(fill=tk.X, pady=5)

        # Decryption Frame
        dec_frame = ttk.LabelFrame(self.root, text="Decryption", padding="10")
        dec_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(dec_frame, text="Private Key File:").pack(anchor=tk.W)
        self.priv_key_entry = ttk.Entry(dec_frame)
        self.priv_key_entry.pack(fill=tk.X, pady=2)
        ttk.Button(dec_frame, text="Browse", command=lambda: self.browse_file(self.priv_key_entry)).pack(anchor=tk.E)

        ttk.Label(dec_frame, text="File to Decrypt:").pack(anchor=tk.W)
        self.cipher_file_entry = ttk.Entry(dec_frame)
        self.cipher_file_entry.pack(fill=tk.X, pady=2)
        ttk.Button(dec_frame, text="Browse", command=lambda: self.browse_file(self.cipher_file_entry)).pack(anchor=tk.E)

        ttk.Button(dec_frame, text="Decrypt File", command=self.decrypt_file).pack(fill=tk.X, pady=5)

        # Status Bar
        self.status_label = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_label.pack(fill=tk.X, padx=10, pady=5, side=tk.BOTTOM)
        
        # Information Labels
        info_frame = ttk.Frame(self.root)
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(info_frame, text="RSA-OAEP Implementation", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        ttk.Label(info_frame, text="• 2048-bit RSA keys").pack(anchor=tk.W)
        ttk.Label(info_frame, text="• SHA-256 hash function").pack(anchor=tk.W)
        ttk.Label(info_frame, text="• Custom implementation (no crypto libs)").pack(anchor=tk.W)
        
if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()