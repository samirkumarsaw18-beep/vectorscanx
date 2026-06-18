import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

def get_file_hash(file_path):
    """Calculates the SHA256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(4096):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def select_file_and_get_hash():
    """Opens a file dialog and shows the hash of the selected file."""
    filepath = filedialog.askopenfilename(title="Select a file to check its hash")
    if filepath:
        file_hash = get_file_hash(filepath)
        print(f"File: {filepath}\nHash: {file_hash}")
        # We will also copy it to the clipboard automatically
        root.clipboard_clear()
        root.clipboard_append(file_hash)
        messagebox.showinfo("File Hash", f"The hash of the file is:\n\n{file_hash}\n\nIt has been copied to your clipboard.")

# --- GUI Setup ---
root = tk.Tk()
root.title("Hash Checker Tool")

label = tk.Label(root, text="Select a file to find its true SHA256 hash.", padx=20, pady=20)
label.pack()

button = tk.Button(root, text="Select File", command=select_file_and_get_hash, font=("Helvetica", 12, "bold"))
button.pack(pady=10)

root.mainloop()
