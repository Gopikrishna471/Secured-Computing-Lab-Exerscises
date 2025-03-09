import tkinter as tk
from tkinter import messagebox

def encrypt_text():
    shift = shift_value.get()
    text = input_text.get("1.0", tk.END).strip()
    encrypted = ''.join([chr(((ord(char) - 32 + shift) % 95) + 32) if 32 <= ord(char) <= 126 else char for char in text])
    encrypted_text.set(encrypted)

def decrypt_text():
    shift = shift_value.get()
    text = encrypted_text.get()
    decrypted = ''.join([chr(((ord(char) - 32 - shift) % 95) + 32) if 32 <= ord(char) <= 126 else char for char in text])
    decrypted_text.set(decrypted)

def clear_all():
    input_text.delete("1.0", tk.END)
    encrypted_text.set("")
    decrypted_text.set("")

# Initialize the main window
root = tk.Tk()
root.title("Caesar Cipher GUI")
root.geometry("700x500")
root.configure(bg="#f0f8ff")

# Input Text Label and TextBox
tk.Label(root, text="Enter Text:", font=("Arial", 14), bg="#f0f8ff").pack(pady=5)
input_text = tk.Text(root, height=3, width=60, font=("Arial", 12), bd=2, relief=tk.GROOVE)
input_text.pack(pady=5)

# Shift Value Label and Scale
tk.Label(root, text="Shift Value:", font=("Arial", 14), bg="#f0f8ff").pack(pady=5)
shift_value = tk.IntVar(value=2)
tk.Scale(root, from_=1, to=25, orient=tk.HORIZONTAL, variable=shift_value, bg="#f0f8ff", troughcolor="#87cefa", bd=0, highlightbackground="#f0f8ff").pack(pady=5)

# Encrypt Button and Encrypted Text Display
frame_encrypt = tk.Frame(root, bg="#f0f8ff")
frame_encrypt.pack(pady=10)
encrypt_button = tk.Button(frame_encrypt, text="Encrypt", font=("Arial", 12), bg="lightgreen", command=encrypt_text, width=10)
encrypt_button.pack(side=tk.LEFT, padx=10)

tk.Label(frame_encrypt, text="Cipher Text:", font=("Arial", 12), bg="#f0f8ff").pack(side=tk.LEFT, padx=5)

encrypted_text = tk.StringVar()
encrypted_entry = tk.Entry(frame_encrypt, textvariable=encrypted_text, font=("Arial", 12), width=50, bd=2, relief=tk.GROOVE)
encrypted_entry.pack(side=tk.LEFT)

# Decrypt Button and Decrypted Text Display
frame_decrypt = tk.Frame(root, bg="#f0f8ff")
frame_decrypt.pack(pady=10)
decrypt_button = tk.Button(frame_decrypt, text="Decrypt", font=("Arial", 12), bg="lightcoral", command=decrypt_text, width=10)
decrypt_button.pack(side=tk.LEFT, padx=10)

tk.Label(frame_decrypt, text="Decrypted Text:", font=("Arial", 12), bg="#f0f8ff").pack(side=tk.LEFT, padx=5)

decrypted_text = tk.StringVar()
decrypted_entry = tk.Entry(frame_decrypt, textvariable=decrypted_text, font=("Arial", 12), width=50, bd=2, relief=tk.GROOVE)
decrypted_entry.pack(side=tk.LEFT)

# Cancel Button
tk.Button(root, text="Clear", font=("Arial", 12), bg="orange", command=clear_all, width=10).pack(pady=20)

# Footer
tk.Label(root, text="@Parasaram Akhil Seshu 99220040673", font=("Arial", 10), fg="gray", bg="#f0f8ff").pack(side=tk.BOTTOM, pady=10)

root.mainloop()