import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
from pathlib import Path

class ColorfulDigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature & Certificate System")
        self.root.geometry("750x600")
        
        # Bright color palette
        self.colors = {
            "background": "#FAFAFA",
            "header": "#6200EA",    # Deep purple
            "key_card": "#00B0FF",  # Light blue
            "file_card": "#00C853", # Green
            "status_card": "#FF6D00", # Orange
            "button": "#6200EA",    # Deep purple
            "button_text": "white",
            "accent": "#FF4081",    # Pink accent
            "text": "#212121",      # Near black
            "light_text": "white"
        }
        
        # Set the background color
        self.root.configure(bg=self.colors["background"])

        # Initialize variables
        self.current_file = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready to go!")

        self.create_gui()

    def create_gui(self):
        # Add colorful header
        header_frame = tk.Frame(self.root, bg=self.colors["header"], height=80)
        header_frame.pack(fill=tk.X)
        
        # Big friendly title
        tk.Label(
            header_frame, 
            text="🔐 Digital Signature & Certificate System", 
            font=("Arial", 24, "bold"), 
            fg=self.colors["light_text"],
            bg=self.colors["header"],
            pady=20
        ).pack()
        
        # Main content area
        content_frame = tk.Frame(self.root, bg=self.colors["background"], padx=20, pady=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create three colorful card sections
        self.create_key_section(content_frame)
        self.create_file_section(content_frame)
        self.create_status_section(content_frame)

    def create_key_section(self, parent):
        # Colorful key card
        card = tk.Frame(
            parent, 
            bg=self.colors["key_card"], 
            padx=15, 
            pady=15, 
            relief=tk.RAISED,
            borderwidth=1
        )
        card.pack(fill=tk.X, pady=10)
        
        # Section title with emoji
        tk.Label(
            card,
            text="🔑 Key Management",
            font=("Arial", 16, "bold"),
            fg=self.colors["light_text"],
            bg=self.colors["key_card"]
        ).pack(anchor=tk.W)
        
        # Generate key button
        generate_btn = tk.Button(
            card,
            text="Generate New Keys",
            font=("Arial", 12),
            bg=self.colors["button"],
            fg=self.colors["button_text"],
            padx=10,
            pady=8,
            relief=tk.RAISED,
            borderwidth=0,
            command=self.generate_keys
        )
        generate_btn.pack(pady=15, fill=tk.X)
        
        # Key status
        self.key_status = tk.Label(
            card,
            text="No keys generated yet",
            font=("Arial", 12),
            fg=self.colors["light_text"],
            bg=self.colors["key_card"]
        )
        self.key_status.pack(pady=5)

    def create_file_section(self, parent):
        # Colorful file card
        card = tk.Frame(
            parent, 
            bg=self.colors["file_card"], 
            padx=15, 
            pady=15, 
            relief=tk.RAISED,
            borderwidth=1
        )
        card.pack(fill=tk.X, pady=10)
        
        # Section title with emoji
        tk.Label(
            card,
            text="📄 File Operations",
            font=("Arial", 16, "bold"),
            fg=self.colors["light_text"],
            bg=self.colors["file_card"]
        ).pack(anchor=tk.W)
        
        # File selection area
        file_frame = tk.Frame(card, bg=self.colors["file_card"], pady=10)
        file_frame.pack(fill=tk.X)
        
        # File entry and browse button
        file_entry = tk.Entry(
            file_frame,
            textvariable=self.current_file,
            font=("Arial", 12),
            bg="white",
            fg=self.colors["text"],
            width=40
        )
        file_entry.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)
        
        browse_btn = tk.Button(
            file_frame,
            text="Browse",
            font=("Arial", 12),
            bg=self.colors["button"],
            fg=self.colors["button_text"],
            padx=10,
            command=self.browse_file
        )
        browse_btn.pack(side=tk.RIGHT)
        
        # Action buttons frame
        button_frame = tk.Frame(card, bg=self.colors["file_card"], pady=10)
        button_frame.pack(fill=tk.X)
        
        # Sign button
        sign_btn = tk.Button(
            button_frame,
            text="✍ Sign File",
            font=("Arial", 12),
            bg=self.colors["button"],
            fg=self.colors["button_text"],
            padx=10,
            pady=8,
            width=15,
            command=self.sign_file
        )
        sign_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Verify button
        verify_btn = tk.Button(
            button_frame,
            text="✓ Verify Signature",
            font=("Arial", 12),
            bg=self.colors["button"],
            fg=self.colors["button_text"],
            padx=10,
            pady=8,
            width=15,
            command=self.verify_signature
        )
        verify_btn.pack(side=tk.LEFT)

    def create_status_section(self, parent):
        # Colorful status card
        card = tk.Frame(
            parent, 
            bg=self.colors["status_card"], 
            padx=15, 
            pady=15, 
            relief=tk.RAISED,
            borderwidth=1
        )
        card.pack(fill=tk.X, pady=10)
        
        # Section title with emoji
        tk.Label(
            card,
            text="📊 Status",
            font=("Arial", 16, "bold"),
            fg=self.colors["light_text"],
            bg=self.colors["status_card"]
        ).pack(anchor=tk.W)
        
        # Status message
        self.status_label = tk.Label(
            card,
            textvariable=self.status_var,
            font=("Arial", 12, "bold"),
            fg=self.colors["light_text"],
            bg=self.colors["status_card"],
            pady=5
        )
        self.status_label.pack(fill=tk.X)

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select a file to sign or verify",
            filetypes=[("All Files", ".")]
        )
        if filename:
            self.current_file.set(filename)
            self.status_var.set(f"Selected: {Path(filename).name}")

    def generate_keys(self):
        try:
            # Update status
            self.status_var.set("Generating keys... Please wait.")
            self.root.update()
            
            # Generate key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()

            # Create keys directory if it doesn't exist
            os.makedirs("keys", exist_ok=True)

            # Save private key
            with open("keys/private_key.pem", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Save public key
            with open("keys/public_key.pem", "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            # Update UI
            self.key_status.config(text="✅ Keys generated and saved in 'keys' folder")
            self.status_var.set("🎉 Keys generated successfully!")
            messagebox.showinfo("Success", "Encryption keys have been generated!")

        except Exception as e:
            self.status_var.set(f"❌ Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")

    def sign_file(self):
        if not self.current_file.get():
            messagebox.showwarning("No File Selected", "Please select a file first!")
            return

        try:
            # Update status
            self.status_var.set("Signing file... Please wait.")
            self.root.update()
            
            # Check if keys exist
            if not os.path.exists("keys/private_key.pem"):
                messagebox.showwarning("No Keys", "Please generate keys first!")
                self.status_var.set("No keys available. Generate keys first.")
                return

            # Load private key
            with open("keys/private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None
                )

            # Read file data
            with open(self.current_file.get(), "rb") as f:
                data = f.read()

            # Sign the data
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Create signatures directory if it doesn't exist
            os.makedirs("signatures", exist_ok=True)

            # Save signature file
            file_name = Path(self.current_file.get()).name
            signature_path = f"signatures/{file_name}.sig"
            with open(signature_path, "wb") as f:
                f.write(signature)

            # Update UI
            self.status_var.set(f"✅ File signed successfully!")
            messagebox.showinfo("Success", f"File has been signed!\nSignature saved as: {signature_path}")

        except Exception as e:
            self.status_var.set(f"❌ Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to sign file: {str(e)}")

    def verify_signature(self):
        if not self.current_file.get():
            messagebox.showwarning("No File Selected", "Please select a file first!")
            return

        try:
            # Update status
            self.status_var.set("Select the signature file...")
            
            # Let user select the signature file
            sig_file = filedialog.askopenfilename(
                title="Select Signature File",
                filetypes=[("Signature Files", ".sig"), ("All Files", ".*")],
                initialdir="signatures"
            )
            
            if not sig_file:
                self.status_var.set("Verification cancelled.")
                return
            
            self.status_var.set("Verifying signature... Please wait.")
            self.root.update()
            
            # Check if public key exists
            if not os.path.exists("keys/public_key.pem"):
                messagebox.showwarning("No Keys", "Please generate keys first!")
                self.status_var.set("No public key available. Generate keys first.")
                return

            # Load public key
            with open("keys/public_key.pem", "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read())

            # Read file data and signature
            with open(self.current_file.get(), "rb") as f:
                data = f.read()
            with open(sig_file, "rb") as f:
                signature = f.read()

            # Verify the signature
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Update UI
            self.status_var.set("✅ Signature verified! File is authentic.")
            messagebox.showinfo("Success", "Signature verified successfully!\nThe file is authentic and has not been tampered with.")

        except Exception as e:
            self.status_var.set("❌ Signature verification failed!")
            messagebox.showerror("Verification Failed", "The signature is invalid or the file has been tampered with!")

if __name__ == "__main__":
    root = tk.Tk()
    app = ColorfulDigitalSignatureApp(root)
    root.mainloop()