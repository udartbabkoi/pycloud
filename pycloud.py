#!/usr/bin/env python3
"""
Telegram Cloud Upload & Rebuild (Bot-only, no local manifests)
Requirements: pip install requests
"""

import os
import math
import json
import time
import tempfile
import shutil
import re
import threading
from pathlib import Path
from tkinter import Tk, Label, Entry, Button, Listbox, END, StringVar, filedialog, Scrollbar, messagebox
from tkinter.ttk import Progressbar
import requests

# ----------------- Config / Helpers -----------------
DEFAULT_CHUNK_SIZE = 1024**3  # 1GB
API_URL = "https://api.telegram.org/bot{token}/{method}"
PART_RE = re.compile(r'^part0*(\d+)_+(?P<orig>.+)$', re.IGNORECASE)

def parse_size(s):
    s = str(s).strip().upper()
    m = re.match(r'^(\d+(?:\.\d+)?)([KMGTP]?)(B)?$', s)
    if not m:
        raise ValueError("Invalid size format")
    num = float(m.group(1))
    unit = m.group(2)
    mul = {'':1, 'K':1024, 'M':1024**2, 'G':1024**3, 'T':1024**4, 'P':1024**5}
    return int(num * mul[unit])

# ----------------- Main App -----------------
class TGCloudBotApp:
    def __init__(self, root):
        self.root = root
        root.title("Telegram Cloud Bot")
        root.geometry("750x560")

        # ---- Config Inputs ----
        Label(root, text="Bot Token:").place(x=10, y=10)
        self.token_var = StringVar()
        Entry(root, textvariable=self.token_var, width=60).place(x=100, y=10)

        Label(root, text="Channel Chat ID:").place(x=10, y=40)
        self.chat_var = StringVar()
        Entry(root, textvariable=self.chat_var, width=30).place(x=130, y=40)

        Label(root, text="Chunk Size:").place(x=10, y=70)
        self.chunk_var = StringVar(value="1G")
        Entry(root, textvariable=self.chunk_var, width=10).place(x=100, y=70)
        Label(root, text="(e.g. 1G, 500M)").place(x=210, y=70)

        Button(root, text="Select Files...", command=self.select_files).place(x=10, y=100)
        Button(root, text="Start Upload", command=self.start_upload).place(x=130, y=100)

        self.files_listbox = Listbox(root, width=85, height=6)
        self.files_listbox.place(x=10, y=130)
        sb = Scrollbar(root, command=self.files_listbox.yview)
        sb.place(x=675, y=130, height=100)
        self.files_listbox.config(yscrollcommand=sb.set)

        Label(root, text="Progress:").place(x=10, y=240)
        self.progress_label = Label(root, text="Idle")
        self.progress_label.place(x=80, y=240)
        self.progress = Progressbar(root, length=580, mode='determinate')
        self.progress.place(x=10, y=265)

        # ---- Rebuild section ----
        Label(root, text="Uploaded Files in Channel:").place(x=10, y=295)
        self.cloud_listbox = Listbox(root, width=85, height=8)
        self.cloud_listbox.place(x=10, y=315)
        sb2 = Scrollbar(root, command=self.cloud_listbox.yview)
        sb2.place(x=675, y=315, height=130)
        self.cloud_listbox.config(yscrollcommand=sb2.set)

        Button(root, text="Scan Channel", command=self.scan_channel).place(x=10, y=450)
        Button(root, text="Rebuild Selected", command=self.rebuild_selected).place(x=120, y=450)

        Label(root, text="Log:").place(x=10, y=480)
        self.log_box = Listbox(root, width=110, height=6)
        self.log_box.place(x=10, y=500)

        # ---- Internal ----
        self.selected_files = []
        self.manifests = {}  # orig_name -> {'message_id': ..., 'parts': [...]}

    def log(self, *args):
        line = " ".join(str(a) for a in args)
        ts = time.strftime("%H:%M:%S")
        self.log_box.insert(END, f"[{ts}] {line}")
        self.log_box.see(END)
        print(line)

    # ---- Upload ----
    def select_files(self):
        files = filedialog.askopenfilenames(title="Select files to upload")
        if not files:
            return
        self.selected_files = list(files)
        self.files_listbox.delete(0, END)
        for f in self.selected_files:
            self.files_listbox.insert(END, f)

    def start_upload(self):
        if not self.selected_files:
            self.log("No files selected for upload.")
            return
        t = threading.Thread(target=self._upload_thread, daemon=True)
        t.start()

    def _upload_thread(self):
        token = self.token_var.get().strip()
        chat_id = self.chat_var.get().strip()
        try:
            chunk_size = parse_size(self.chunk_var.get())
        except Exception as e:
            self.log("Invalid chunk size:", e)
            return

        total_parts = sum(math.ceil(os.path.getsize(f)/chunk_size) for f in self.selected_files)
        uploaded_parts = 0

        for filepath in self.selected_files:
            path = Path(filepath)
            fname = path.name
            size = path.stat().st_size
            parts_count = math.ceil(size / chunk_size)
            parts_names = []

            self.log(f"Uploading {fname}, size={size}, parts={parts_count}")
            with open(path, 'rb') as f:
                for i in range(1, parts_count+1):
                    chunk = f.read(chunk_size)
                    part_name = f"part{i:03d}_{fname}"
                    tmp_file = tempfile.NamedTemporaryFile(delete=False)
                    tmp_file.write(chunk)
                    tmp_file.close()

                    if not self._upload_file(token, chat_id, tmp_file.name, caption=part_name):
                        self.log("Failed to upload part:", part_name)
                        os.unlink(tmp_file.name)
                        return
                    os.unlink(tmp_file.name)
                    parts_names.append(part_name)

                    uploaded_parts += 1
                    self.progress['maximum'] = total_parts
                    self.progress['value'] = uploaded_parts
                    self.progress_label.config(text=f"Uploaded {uploaded_parts}/{total_parts} parts")
                    self.root.update_idletasks()

            manifest_text = f"🔗 Manifest: {fname}\n" + "\n".join(parts_names)
            manifest_msg_id = self._post_message(token, chat_id, manifest_text)
            if manifest_msg_id:
                self.log(f"Manifest posted for {fname} (msg_id={manifest_msg_id})")
            else:
                self.log(f"Failed to post manifest for {fname}")

        self.progress_label.config(text="Upload done ✅")
        self.log("All uploads finished.")

    def _upload_file(self, token, chat_id, path, caption=""):
        url = API_URL.format(token=token, method="sendDocument")
        for attempt in range(1, 4):
            try:
                with open(path, 'rb') as fh:
                    files = {"document": (Path(path).name, fh)}
                    data = {"chat_id": chat_id, "caption": caption}
                    r = requests.post(url, data=data, files=files, timeout=120)
                if r.status_code == 200:
                    return True
            except Exception as e:
                self.log(f"Attempt {attempt} failed for {path}: {e}")
        return False

    def _post_message(self, token, chat_id, text):
        url = API_URL.format(token=token, method="sendMessage")
        try:
            r = requests.post(url, data={"chat_id": chat_id, "text": text})
            if r.status_code == 200:
                res = r.json()
                return res['result']['message_id']
        except Exception as e:
            self.log("Failed to post manifest:", e)
        return None

    def scan_channel(self):
        t = threading.Thread(target=self._scan_channel_thread, daemon=True)
        t.start()

    def _scan_channel_thread(self):
        token = self.token_var.get().strip()
        chat_id = self.chat_var.get().strip()
        self.cloud_listbox.delete(0, END)
        self.manifests.clear()
        self.log("Scanning channel for manifests...")

        offset = 0
        while True:
            url = API_URL.format(token=token, method="getUpdates")
            r = requests.get(url)
            if r.status_code != 200:
                self.log("Failed to get updates:", r.text)
                return
            data = r.json()
            updates = data.get("result", [])
            found_any = False
            for u in updates:
                msg = u.get("message")
                if not msg:
                    continue
                if msg.get("chat", {}).get("id") != int(chat_id):
                    continue
                text = msg.get("text", "")
                if text.startswith("🔗 Manifest:"):
                    lines = text.splitlines()
                    orig = lines[0].split(":",1)[1].strip()
                    parts = lines[1:]
                    self.manifests[orig] = {"message_id": msg["message_id"], "parts": parts}
                    self.cloud_listbox.insert(END, f"{orig}  ({len(parts)} parts)")
                    found_any = True
            if not found_any:
                break
            offset += 100
        self.log(f"Scan complete. Found {len(self.manifests)} files.")

    def rebuild_selected(self):
        sel = self.cloud_listbox.curselection()
        if not sel:
            messagebox.showinfo("Select file", "Please select a file to rebuild.")
            return
        idx = sel[0]
        fname = self.cloud_listbox.get(idx).split("  ")[0]
        manifest = self.manifests.get(fname)
        if not manifest:
            messagebox.showerror("Error", "Manifest not found for selected file.")
            return
        parts = manifest["parts"]
        outdir = filedialog.askdirectory(title="Choose folder to save rebuilt file")
        if not outdir:
            return
        t = threading.Thread(target=self._rebuild_thread, args=(fname, parts, outdir), daemon=True)
        t.start()

    def _rebuild_thread(self, orig_name, parts, outdir):
        token = self.token_var.get().strip()
        chat_id = self.chat_var.get().strip()
        tmpdir = Path(tempfile.mkdtemp(prefix="tg_rebuild_"))
        self.log(f"Downloading parts for {orig_name} into tempdir {tmpdir}")
        try:
            for i, part_name in enumerate(parts, 1):
                url = API_URL.format(token=token, method="getUpdates")
                r = requests.get(url)
                if r.status_code != 200:
                    self.log(f"Failed to get updates for part {part_name}")
                    return
                found = False
                for u in r.json().get("result", []):
                    msg = u.get("message")
                    if not msg:
                        continue
                    if msg.get("chat", {}).get("id") != int(chat_id):
                        continue
                    if msg.get("caption") == part_name:
                        file_info = msg.get("document")
                        if not file_info:
                            continue
                        file_id = file_info["file_id"]
                        file_path = tmpdir / part_name
                        self.log(f"Downloading {part_name}...")
                        dl_url = f"https://api.telegram.org/bot{token}/getFile?file_id={file_id}"
                        resp = requests.get(dl_url)
                        if resp.status_code != 200:
                            self.log(f"Failed to get file path for {part_name}")
                            return
                        file_path_resp = resp.json()
                        file_path_str = file_path_resp["result"]["file_path"]
                        download_url = f"https://api.telegram.org/file/bot{token}/{file_path_str}"
                        with requests.get(download_url, stream=True) as r2, open(file_path, "wb") as f:
                            shutil.copyfileobj(r2.raw, f)
                        found = True
                        break
                if not found:
                    self.log(f"Part {part_name} not found in channel")
                    messagebox.showwarning("Missing part", f"{part_name} not found")
                    return
            out_file_path = Path(outdir) / orig_name
            self.log(f"Merging parts into {out_file_path}...")
            with open(out_file_path, "wb") as outfh:
                for part_name in parts:
                    p = tmpdir / part_name
                    with open(p, "rb") as pf:
                        shutil.copyfileobj(pf, outfh)
            self.log(f"File rebuilt: {out_file_path}")
            messagebox.showinfo("Rebuild complete", f"Rebuilt file saved to:\n{out_file_path}")
        finally:
            shutil.rmtree(tmpdir)
            self.log("Tempdir cleaned up.")

# ---- Main ----
def main():
    root = Tk()
    app = TGCloudBotApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
