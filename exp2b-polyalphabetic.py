import tkinter as tk
from tkinter import messagebox

def encrypt():
    text = input_text.get()
    keyword = keyword_entry.get()
    
    if not text or not keyword:
        messagebox.showwarning("Warning", "Please enter both text and keyword")
        return
        
    if not keyword.isalnum():  # Changed to isalnum() to accept both letters and numbers
        messagebox.showerror("Error", "Keyword must contain only letters and numbers")
        return
        
    result = ""
    keyword = keyword.upper()
    key_length = len(keyword)
    key_index = 0
    
    for char in text:
        if char.isalpha():
            # Get shift value from keyword
            key_char = keyword[key_index % key_length]
            # If key character is a number, use it directly as shift value
            if key_char.isdigit():
                shift = int(key_char)
            # If key character is a letter, calculate shift as before
            else:
                shift = ord(key_char) - ord('A')
                
            # Determine case and base
            ascii_base = ord('A') if char.isupper() else ord('a')
            # Calculate new position
            new_pos = (ord(char.upper()) - ord('A') + shift) % 26
            # Convert back to original case
            result += chr(ascii_base + new_pos)
            key_index += 1
        else:
            result += char
            
    encrypted_text.delete(0, tk.END)
    encrypted_text.insert(0, result)

def decrypt():
    text = encrypted_text.get()
    keyword = keyword_entry.get()
    
    if not text or not keyword:
        messagebox.showwarning("Warning", "Please enter both text and keyword")
        return
        
    if not keyword.isalnum():  # Changed to isalnum() to accept both letters and numbers
        messagebox.showerror("Error", "Keyword must contain only letters and numbers")
        return
        
    result = ""
    keyword = keyword.upper()
    key_length = len(keyword)
    key_index = 0
    
    for char in text:
        if char.isalpha():
            # Get shift value from keyword
            key_char = keyword[key_index % key_length]
            # If key character is a number, use it directly as shift value
            if key_char.isdigit():
                shift = int(key_char)
            # If key character is a letter, calculate shift as before
            else:
                shift = ord(key_char) - ord('A')
                
            # Determine case and base
            ascii_base = ord('A') if char.isupper() else ord('a')
            # Calculate new position (reverse shift)
            new_pos = (ord(char.upper()) - ord('A') - shift) % 26
            # Convert back to original case
            result += chr(ascii_base + new_pos)
            key_index += 1
        else:
            result += char
            
    decrypted_text.delete(0, tk.END)
    decrypted_text.insert(0, result)

def clear():
    input_text.delete(0, tk.END)
    keyword_entry.delete(0, tk.END)
    encrypted_text.delete(0, tk.END)
    decrypted_text.delete(0, tk.END)

# Create main window
window = tk.Tk()
window.title("Polyalphabetic Cipher")
window.geometry("500x300")

# Create and place widgets
tk.Label(window, text="Enter Text:").pack()
input_text = tk.Entry(window, width=50)
input_text.pack()

tk.Label(window, text="Enter Keyword (letters and numbers):").pack()
keyword_entry = tk.Entry(window, width=30)
keyword_entry.pack()

# Create frame for encrypt section
tk.Label(window, text="Cipher Text").pack()
encrypt_frame = tk.Frame(window)
encrypt_frame.pack(pady=10)
tk.Button(encrypt_frame, text="Encrypt", command=encrypt).pack(side=tk.LEFT, padx=5)

encrypted_text = tk.Entry(encrypt_frame, width=50)
encrypted_text.pack(side=tk.LEFT)

# Create frame for decrypt section
tk.Label(window, text="Decrypted Text").pack()
decrypt_frame = tk.Frame(window)
decrypt_frame.pack(pady=10)
tk.Button(decrypt_frame, text="Decrypt", command=decrypt).pack(side=tk.LEFT, padx=5)
decrypted_text = tk.Entry(decrypt_frame, width=50)
decrypted_text.pack(side=tk.LEFT)

# Clear button
tk.Button(window, text="Clear", command=clear).pack(pady=10)

window.mainloop()