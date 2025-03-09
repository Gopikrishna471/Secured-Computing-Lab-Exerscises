import tkinter as tk
from tkinter import messagebox
import hashlib

class ColorfulSHA1Calculator:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("SHA-1 Message Digest Calculator")
        self.window.geometry("600x700")
        self.window.configure(bg="#2C3E50")  # Dark blue background
        
        # Title
        title = tk.Label(self.window, 
                        text="SHA-1 Calculator",
                        font=("Arial", 24, "bold"),
                        bg="#2C3E50",
                        fg="#ECF0F1")  # White text
        title.pack(pady=20)
        
        # Main frame
        main_frame = tk.Frame(self.window, bg="#34495E", padx=20, pady=20)
        main_frame.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Input Frame 1
        input_frame1 = tk.Frame(main_frame, bg="#34495E")
        input_frame1.pack(fill="x", pady=10)
        
        tk.Label(input_frame1,
                text="Enter name with initial at start:",
                font=("Arial", 12),
                bg="#34495E",
                fg="#ECF0F1").pack(anchor="w")
        
        self.input1 = tk.Entry(input_frame1,
                             font=("Arial", 12),
                             bg="#ECF0F1",
                             fg="#2C3E50",
                             relief="flat")
        self.input1.pack(fill="x", pady=5)
        
        # Input Frame 2
        input_frame2 = tk.Frame(main_frame, bg="#34495E")
        input_frame2.pack(fill="x", pady=10)
        
        tk.Label(input_frame2,
                text="Enter name with initial at end:",
                font=("Arial", 12),
                bg="#34495E",
                fg="#ECF0F1").pack(anchor="w")
        
        self.input2 = tk.Entry(input_frame2,
                             font=("Arial", 12),
                             bg="#ECF0F1",
                             fg="#2C3E50",
                             relief="flat")
        self.input2.pack(fill="x", pady=5)
        
        # Buttons Frame
        button_frame = tk.Frame(main_frame, bg="#34495E")
        button_frame.pack(pady=20)
        
        # Calculate Button
        self.calc_button = tk.Button(button_frame,
                                   text="Calculate Hash",
                                   font=("Arial", 12, "bold"),
                                   bg="#3498DB",  # Blue
                                   fg="white",
                                   relief="flat",
                                   command=self.calculate_hash,
                                   padx=20,
                                   pady=10,
                                   state='disabled')  # Initially disabled
        self.calc_button.pack(side="left", padx=5)
        
        # Clear Button
        self.clear_button = tk.Button(button_frame,
                                    text="Clear All",
                                    font=("Arial", 12, "bold"),
                                    bg="#E74C3C",  # Red
                                    fg="white",
                                    relief="flat",
                                    command=self.clear_fields,
                                    padx=20,
                                    pady=10)
        self.clear_button.pack(side="left", padx=5)
        
        # Results Frame
        results_frame = tk.Frame(main_frame, bg="#34495E")
        results_frame.pack(fill="x", pady=20)
        
        # Hash Results
        tk.Label(results_frame,
                text="Hash Result 1:",
                font=("Arial", 12),
                bg="#34495E",
                fg="#ECF0F1").pack(anchor="w")
        
        self.hash1_result = tk.Entry(results_frame,
                                   font=("Courier", 10),
                                   bg="#ECF0F1",
                                   fg="#2C3E50",
                                   relief="flat",
                                   state='readonly')
        self.hash1_result.pack(fill="x", pady=5)
        
        tk.Label(results_frame,
                text="Hash Result 2:",
                font=("Arial", 12),
                bg="#34495E",
                fg="#ECF0F1").pack(anchor="w")
        
        self.hash2_result = tk.Entry(results_frame,
                                   font=("Courier", 10),
                                   bg="#ECF0F1",
                                   fg="#2C3E50",
                                   relief="flat",
                                   state='readonly')
        self.hash2_result.pack(fill="x", pady=5)
        
        # Status Label
        self.status_label = tk.Label(results_frame,
                                   text="",
                                   font=("Arial", 14, "bold"),
                                   bg="#34495E",
                                   fg="#2ECC71")
        self.status_label.pack(pady=20)
        
        # Button hover effects
        self.calc_button.bind("<Enter>", self.on_enter)
        self.calc_button.bind("<Leave>", self.on_leave)
        self.clear_button.bind("<Enter>", lambda e: e.widget.config(bg="#C0392B"))
        self.clear_button.bind("<Leave>", lambda e: e.widget.config(bg="#E74C3C"))
        
        # Bind input validation to both entry fields
        self.input1.bind('<KeyRelease>', self.validate_inputs)
        self.input2.bind('<KeyRelease>', self.validate_inputs)
    
    def validate_inputs(self, event=None):
        """Validate input fields and enable/disable calculate button"""
        if self.input1.get().strip() and self.input2.get().strip():
            self.calc_button.config(state='normal')
        else:
            self.calc_button.config(state='disabled')
    
    def on_enter(self, event):
        """Modified hover effect for calculate button"""
        if self.calc_button['state'] == 'normal':
            self.calc_button.config(bg="#2980B9")
    
    def on_leave(self, event):
        """Modified hover effect for calculate button"""
        if self.calc_button['state'] == 'normal':
            self.calc_button.config(bg="#3498DB")
    
    def calculate_hash(self):
        """Calculate SHA-1 hash and check integrity"""
        input1 = self.input1.get().strip()
        input2 = self.input2.get().strip()
        
        # Calculate hashes
        hash1 = hashlib.sha1(input1.encode()).hexdigest()
        hash2 = hashlib.sha1(input2.encode()).hexdigest()
        
        # Update hash display
        self.hash1_result.config(state='normal')
        self.hash2_result.config(state='normal')
        self.hash1_result.delete(0, tk.END)
        self.hash2_result.delete(0, tk.END)
        self.hash1_result.insert(0, hash1)
        self.hash2_result.insert(0, hash2)
        self.hash1_result.config(state='readonly')
        self.hash2_result.config(state='readonly')
        
        # Update status
        if hash1 == hash2:
            self.status_label.config(text="✓ Integrity Verified!", fg="#2ECC71")
        else:
            self.status_label.config(text="✗ Integrity Check Failed!", fg="#E74C3C")
    
    def clear_fields(self):
        """Clear all fields"""
        self.input1.delete(0, tk.END)
        self.input2.delete(0, tk.END)
        self.hash1_result.config(state='normal')
        self.hash2_result.config(state='normal')
        self.hash1_result.delete(0, tk.END)
        self.hash2_result.delete(0, tk.END)
        self.hash1_result.config(state='readonly')
        self.hash2_result.config(state='readonly')
        self.status_label.config(text="")
        self.calc_button.config(state='disabled')  # Disable calculate button after clearing
    
    def run(self):
        """Start the application"""
        self.window.mainloop()

if __name__ == "__main__":
    app = ColorfulSHA1Calculator()
    app.run()