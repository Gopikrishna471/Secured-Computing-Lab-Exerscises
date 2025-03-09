import tkinter as tk
from tkinter import messagebox
from sympy import mod_inverse

def rsa_encrypt():
    try:
        P = 3
        Q = 11
        E = 3
        N = P * Q
        phi_N = (P - 1) * (Q - 1)
        D = mod_inverse(E, phi_N)
        
        message = int(entry_plaintext.get(), 2)
        ciphertext = pow(message, E, N)
        messagebox.showinfo("Encryption", f"Ciphertext: {ciphertext}\nPrivate Key (D): {D}")
    except ValueError:
        messagebox.showerror("Error", "Invalid input. Please enter a valid binary string.")

def rsa_decrypt():
    try:
        P = 3
        Q = 11
        E = 3
        N = P * Q
        phi_N = (P - 1) * (Q - 1)
        D = mod_inverse(E, phi_N)
        
        ciphertext = int(entry_ciphertext.get())
        decrypted_message = pow(ciphertext, D, N)
        binary_plaintext = bin(decrypted_message)[2:].zfill(8)
        messagebox.showinfo("Decryption", f"Decrypted Binary: {binary_plaintext}")
    except ValueError:
        messagebox.showerror("Error", "Invalid ciphertext input. Please enter a valid number.")

def check_fields():
    if entry_plaintext.get() and entry_ciphertext.get():
        encrypt_button.config(state=tk.NORMAL)
        decrypt_button.config(state=tk.NORMAL)
    else:
        encrypt_button.config(state=tk.DISABLED)
        decrypt_button.config(state=tk.DISABLED)

def exit_program():
    root.destroy()

# GUI setup
root = tk.Tk()
root.title("RSA Encryption & Decryption")

tk.Label(root, text="Enter Plaintext (Binary):").grid(row=0, column=0)
entry_plaintext = tk.Entry(root)
entry_plaintext.grid(row=0, column=1)
entry_plaintext.bind("<KeyRelease>", lambda event: check_fields())

tk.Label(root, text="Enter Ciphertext (Number):").grid(row=1, column=0)
entry_ciphertext = tk.Entry(root)
entry_ciphertext.grid(row=1, column=1)
entry_ciphertext.bind("<KeyRelease>", lambda event: check_fields())

encrypt_button = tk.Button(root, text="Encrypt", command=rsa_encrypt, state=tk.DISABLED, height=2, width=15)
encrypt_button.grid(row=2, columnspan=2, pady=30)

decrypt_button = tk.Button(root, text="Decrypt", command=rsa_decrypt, state=tk.DISABLED, height=2, width=15)
decrypt_button.grid(row=3, columnspan=2, pady=30)

exit_button = tk.Button(root, text="Exit", command=exit_program, height=2, width=15)
exit_button.grid(row=4, columnspan=2, pady=30)

root.mainloop()
