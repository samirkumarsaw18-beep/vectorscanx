import tkinter as tk

print("DEBUG: Script started")
print("DEBUG: Creating tkinter window...")

root = tk.Tk()
print("DEBUG: Root window created")

root.title("Test Window")
root.geometry("400x300")

label = tk.Label(root, text="If you see this window, GUI is working!", font=("Arial", 14))
label.pack(pady=50)

print("DEBUG: Window should be visible now!")
print("DEBUG: Starting mainloop...")

root.mainloop()

print("DEBUG: Window closed")
