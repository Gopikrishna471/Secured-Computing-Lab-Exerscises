import tkinter as tk
from tkinter import ttk, scrolledtext
import des_code as des  # Changed from 'abc' to 'des_code' to avoid conflict

class DESGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DES Encryption/Decryption")
        self.root.geometry("800x600")
        
        # Input Frame
        input_frame = ttk.LabelFrame(root, text="Input", padding="10")
        input_frame.pack(fill="x", padx=10, pady=5)
        
        # Plaintext Input
        ttk.Label(input_frame, text="Plaintext (16 characters hex):").grid(row=0, column=0, padx=5, pady=5)
        self.plaintext = ttk.Entry(input_frame, width=40)
        self.plaintext.grid(row=0, column=1, padx=5, pady=5)
        self.plaintext.insert(0, "123456ABCD132536")  # Default value
        
        # Key Input
        ttk.Label(input_frame, text="Key (16 characters hex):").grid(row=1, column=0, padx=5, pady=5)
        self.key = ttk.Entry(input_frame, width=40)
        self.key.grid(row=1, column=1, padx=5, pady=5)
        self.key.insert(0, "AABB09182736CCDD")  # Default value
        
        # Button Frame
        button_frame = ttk.Frame(root)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        # Process Button
        ttk.Button(button_frame, text="Process Encryption/Decryption", command=self.process_des).pack(pady=5)
        
        # Output Frame
        output_frame = ttk.LabelFrame(root, text="Output", padding="10")
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create scrolled text widget for output
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=20)
        self.output_text.pack(fill="both", expand=True)
        
    def validate_hex_input(self, text):
        """Validate if input is valid hexadecimal and 16 characters long"""
        if len(text) != 16:
            return False
        try:
            int(text, 16)
            return True
        except ValueError:
            return False
            
    def capture_output(self, func):
        """Capture print output from DES functions"""
        import io
        import sys
        
        # Create StringIO object to capture output
        output = io.StringIO()
        # Redirect stdout to our output capture
        sys.stdout = output
        
        # Run the function
        result = func()
        
        # Restore stdout
        sys.stdout = sys.__stdout__
        
        return output.getvalue(), result
        
    def process_des(self):
        """Process DES encryption and decryption"""
        # Clear previous output
        self.output_text.delete(1.0, tk.END)
        
        # Get input values
        pt = self.plaintext.get().upper()
        key = self.key.get().upper()
        
        # Validate input
        if not (self.validate_hex_input(pt) and self.validate_hex_input(key)):
            self.output_text.insert(tk.END, "Error: Please enter valid 16-character hexadecimal values\n")
            return
            
        try:
            # Initialize variables from des.py
            key = des.hex2bin(key)
            
            # Generate key schedule
            # Parity bit drop
            key = des.permute(key, des.keyp, 56)
            
            # Splitting
            left = key[0:28]
            right = key[28:56]
            rkb = []
            rk = []
            
            # Generate round keys
            for i in range(0, 16):
                left = des.shift_left(left, des.shift_table[i])
                right = des.shift_left(right, des.shift_table[i])
                combine_str = left + right
                round_key = des.permute(combine_str, des.key_comp, 48)
                rkb.append(round_key)
                rk.append(des.bin2hex(round_key))
            
            # Encryption
            self.output_text.insert(tk.END, "ENCRYPTION PROCESS:\n" + "="*50 + "\n")
            encryption_output, cipher_text = self.capture_output(
                lambda: des.bin2hex(des.encrypt(pt, rkb, rk))
            )
            self.output_text.insert(tk.END, encryption_output)
            self.output_text.insert(tk.END, f"Final Cipher Text: {cipher_text}\n\n")
            
            # Decryption
            self.output_text.insert(tk.END, "DECRYPTION PROCESS:\n" + "="*50 + "\n")
            rkb_rev = rkb[::-1]
            rk_rev = rk[::-1]
            decryption_output, plain_text = self.capture_output(
                lambda: des.bin2hex(des.encrypt(cipher_text, rkb_rev, rk_rev))
            )
            self.output_text.insert(tk.END, decryption_output)
            self.output_text.insert(tk.END, f"Final Plain Text: {plain_text}\n")
        
        except Exception as e:
            self.output_text.insert(tk.END, f"Error occurred: {str(e)}\n")
            
        # Scroll to top
        self.output_text.see("1.0")

if __name__ == "__main__":
    root = tk.Tk()
    app = DESGUI(root)
    root.mainloop()