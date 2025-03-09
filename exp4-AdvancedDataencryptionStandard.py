from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import tkinter as tk
from tkinter import ttk, messagebox

# Function to convert string to hexadecimal
def string_to_hex(s):
    return ' '.join(format(ord(char), '02X') for char in s)

# AES Encryption Function
def aes_encrypt(key, plaintext):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return binascii.hexlify(ciphertext).decode('utf-8')

# AES Decryption Function
def aes_decrypt(key, ciphertext):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    ciphertext_bytes = binascii.unhexlify(ciphertext)
    plaintext_padded = cipher.decrypt(ciphertext_bytes)
    plaintext = unpad(plaintext_padded, AES.block_size).decode('utf-8')
    return plaintext

class AESEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")
        self.root.geometry("700x500")
        self.root.configure(bg="#f7f9fb")

        # Header Label
        header = tk.Label(self.root, text="AES Encryption/Decryption Tool", font=("Helvetica", 18, "bold"), bg="#0078D7", fg="white", pady=10)
        header.pack(fill=tk.X)

        # Main Frame
        main_frame = tk.Frame(self.root, bg="#f7f9fb", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Key input
        ttk.Label(main_frame, text="Key (16 characters):", font=("Helvetica", 12), background="#f7f9fb").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(main_frame, textvariable=self.key_var, width=50)
        self.key_entry.grid(row=0, column=1, pady=10, padx=10)

        # Plaintext input
        ttk.Label(main_frame, text="Plaintext:", font=("Helvetica", 12), background="#f7f9fb").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.plaintext_var = tk.StringVar()
        self.plaintext_entry = ttk.Entry(main_frame, textvariable=self.plaintext_var, width=50)
        self.plaintext_entry.grid(row=1, column=1, pady=10, padx=10)

        # Ciphertext input/output
        ttk.Label(main_frame, text="Ciphertext (Hex):", font=("Helvetica", 12), background="#f7f9fb").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.ciphertext_var = tk.StringVar()
        self.ciphertext_entry = ttk.Entry(main_frame, textvariable=self.ciphertext_var, width=50)
        self.ciphertext_entry.grid(row=2, column=1, pady=10, padx=10)

        # Buttons
        button_frame = tk.Frame(main_frame, bg="#f7f9fb")
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        encrypt_button = ttk.Button(button_frame, text="Encrypt", command=self.encrypt)
        encrypt_button.grid(row=0, column=0, padx=10)

        decrypt_button = ttk.Button(button_frame, text="Decrypt", command=self.decrypt)
        decrypt_button.grid(row=0, column=1, padx=10)

        # Result display
        ttk.Label(main_frame, text="Result:", font=("Helvetica", 12), background="#f7f9fb").grid(row=4, column=0, sticky=tk.W, pady=10)
        self.result_var = tk.StringVar()
        self.result_entry = ttk.Entry(main_frame, textvariable=self.result_var, width=50, state='readonly')
        self.result_entry.grid(row=4, column=1, pady=10, padx=10)

        # Footer
        footer = tk.Label(self.root, text="AMRUTH SAI -- 99220040641", font=("Helvetica", 10, "italic"), bg="#f7f9fb", fg="gray")
        footer.pack(side=tk.BOTTOM, pady=10)

    def encrypt(self):
        try:
            key = self.key_var.get()
            plaintext = self.plaintext_var.get()
            if len(key) != 16:
                messagebox.showerror("Error", "Key must be exactly 16 characters long!")
                return
            ciphertext = aes_encrypt(key, plaintext)
            self.ciphertext_var.set(ciphertext.upper())
            self.result_var.set("Encryption successful!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt(self):
        try:
            key = self.key_var.get()
            ciphertext = self.ciphertext_var.get()
            if len(key) != 16:
                messagebox.showerror("Error", "Key must be exactly 16 characters long!")
                return
            plaintext = aes_decrypt(key, ciphertext)
            self.result_var.set(f"Decrypted: {plaintext}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

# Main execution
if __name__ == "__main__":
    root = tk.Tk()
    app = AESEncryptionGUI(root)
    root.mainloop()