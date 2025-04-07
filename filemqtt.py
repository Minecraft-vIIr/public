import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import base64
import uuid
import json
import argparse
import os
import sys
import time
import asyncio
import functools

print = functools.partial(print, flush=True)

def exec_path():
    if getattr(sys, "frozen", False):
        application_path = sys.executable
    elif __file__:
        application_path = os.path.abspath(__file__)
    return application_path

def get_file_list(directory, source):
        file_list = {}
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), source)
                    file_list[rel_path] = os.path.join(root, file)
        except Exception as e:
            print(f"!read {directory}: {e}")
        return file_list

def to_chunks(content, chunksize):
        chunks = {}
        for i, chunk in enumerate((content[i:i+chunksize] for i in range(0, len(content), chunksize)), start=1):
            chunks[i] = base64.b64encode(chunk).decode("utf-8")
        return chunks

def encrypt_message(message, key):
    iv = get_random_bytes(AES.block_size)  # Generate a unique IV for each message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_message = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    return base64.b64encode(iv + encrypted_message).decode("utf-8")

def decrypt_message(encrypted_message, key):
    try:
        decoded_message = base64.b64decode(encrypted_message)
        iv = decoded_message[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(decoded_message[AES.block_size:]), AES.block_size)
        return decrypted_message.decode("utf-8")
    except (ValueError, KeyError):
        return None

async def monitor_chunks(fileid, cooldown=10):
    global client, filestatus
    
    while filestatus[fileid]["remainchunk"]:
        await asyncio.sleep(0.5)
        if time.time() - filestatus[fileid]["lastreact"] >= cooldown: # resend chunk
            for chunk in filestatus[fileid]["remainchunk"]:
                content = filestatus[fileid]["remainchunk"][chunk]
                publish_json_message(client, TRANS_TOPIC, {
                    "type": "trans",
                    "fileid": fileid,
                    "chunk": chunk,
                    "content": content,
                    "from": SENDER_ADDR,
                    "to": args.to
                })
            filestatus[fileid]["lastreact"] = time.time()
    print("+all")

# MQTT settings
BROKER = "mqtt.eclipseprojects.io" # "broker.hivemq.com"
PORT = 1883
CTRL_TOPIC  = "FCTRL6/file/ctrl"
TRANS_TOPIC = "FCTRL6/file/trans"
filestatus = {}
filestack = {}

# args
parser = argparse.ArgumentParser(description="MQTT File Transfer Tool")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--send", "-m", action="store_true", help="Act as sender")
group.add_argument("--receive", "-r", action="store_true", help="Act as receiver")
parser.add_argument("--input", "-i", help="Input file (required for send mode)")
parser.add_argument("--to", "-t", help="Target receiver's addr (required for send mode)")
parser.add_argument("--output", "-o", default=os.path.dirname(exec_path()),
                    help="Output directory (default: same directory as this script)")
parser.add_argument("--aeskey", default="c6c1a1f38e0a40dc", help="AES encryption key (16/24/32 chars)")
args = parser.parse_args()
AES_KEY = args.aeskey.encode("utf-8")

if args.send:
    if not args.input:
        parser.error("--input is required in send mode")
    if not args.to:
        parser.error("--to is required in send mode")
elif args.receive:
    OUTPUTDIR = os.path.abspath(args.output)
    os.makedirs(OUTPUTDIR, exist_ok=True)

def on_connect(client, userdata, flags, rc):
    """MQTT connection callback."""
    if rc == 0:
        print("+connected")
        userdata["connected"] = True
        if args.send:
            client.subscribe(CTRL_TOPIC)
        elif args.receive:
            client.subscribe(TRANS_TOPIC)
    else:
        print(f"!connection failed: {rc}")

def on_message(client, userdata, msg):
    """MQTT message callback."""
    global pending_req_confirm, filestatus, filestack

    decrypted_message = decrypt_message(msg.payload.decode("utf-8"), AES_KEY)
    if decrypted_message:
        try:
            message = json.loads(decrypted_message)

            if args.send:
                if message.get("to") != SENDER_ADDR:
                    return
                
                if message.get("type") == "transack" and message.get("fileid") in pending_req_confirm :
                    pending_req_confirm.remove(message.get("fileid"))
                    print("+transack")
                elif message.get("type") == "recvchunk":
                    fileid = message.get("fileid")
                    chunk = message.get("chunk")

                    if fileid in filestatus and chunk in filestatus[fileid]["remainchunk"]:
                        print(f"+ {chunk}")
                        del filestatus[fileid]["remainchunk"][chunk]
                        filestatus[fileid]["lastreact"] = time.time()
            elif args.receive:
                if message.get("to") != RECEIVER_ADDR:
                    return
                
                if message.get("type") == "transreq":
                    fileid = message.get("fileid")
                    filestack[fileid] = {
                        "relfilepath": message.get("relfilepath"),
                        "md5": message.get("md5"),
                        "len": message.get("len"),
                        "chunks": {}
                    }

                    save_path = os.path.join(OUTPUTDIR, filestack[fileid]["relfilepath"])
                    os.makedirs(os.path.dirname(save_path), exist_ok=True)
                    with open(save_path, "wb") as f:
                        f.write(b"")

                    print(f"transreq: {filestack[fileid]['relfilepath']}")
                    publish_json_message(client, CTRL_TOPIC, {
                        "type": "transack",
                        "fileid": fileid,
                        "from": RECEIVER_ADDR,
                        "to": message.get("from")
                    })

                    if message.get("len") == 0:
                        print(f"+saved: {save_path}")
                elif message.get("type") == "trans":
                    fileid = message.get("fileid")
                    if fileid in filestack:
                        chunk = message.get("chunk")
                        content = message.get("content")
                        filestack[fileid]["chunks"][chunk] = content # saved chunk

                        publish_json_message(client, CTRL_TOPIC, {
                            "type": "recvchunk",
                            "fileid": fileid,
                            "chunk": chunk,
                            "from": RECEIVER_ADDR,
                            "to": message.get("from")
                        })

                        if len(filestack[fileid]["chunks"]) == filestack[fileid]["len"]:
                            save_path = os.path.join(OUTPUTDIR, filestack[fileid]["relfilepath"])
                            # os.makedirs(os.path.dirname(save_path), exist_ok=True)
                            with open(save_path, "wb") as f:
                                for i in range(1, filestack[fileid]["len"] + 1):
                                    f.write(base64.b64decode(filestack[fileid]["chunks"][i].encode()))
                            print(f"+saved: {save_path}")
                            del filestack[fileid]

        except json.JSONDecodeError:
            print("!JSON")
    else:
        print("!decrypt")

def publish_json_message(client, topic, json_message):
    """Encrypt and publish a JSON message."""
    message = json.dumps(json_message)
    encrypted_message = encrypt_message(message, AES_KEY)
    client.publish(topic, encrypted_message)

pending_req_confirm = []

async def main():
    global client, pending_req_confirm, filestatus

    print("+connecting")
    
    userdata = {"connected": False}
    client = mqtt.Client(client_id=uuid.uuid4().hex, userdata=userdata)
    client.on_connect = on_connect
    client.on_message = on_message

    while True:
        try:
            client.connect(BROKER, PORT, 60)
            break
        except Exception as e:
            print(f"!retry")
            time.sleep(3)
    
    client.loop_start()

    # Wait for connection
    while not userdata["connected"]:
        await asyncio.sleep(0.1)

    try:
        if args.send:
            global SENDER_ADDR
            SENDER_ADDR = uuid.uuid4().hex

            sourcepath = args.input.strip('"')
            if os.path.isdir(sourcepath):
                filepaths = get_file_list(sourcepath, os.path.dirname(sourcepath))
            else:
                filepaths = {os.path.basename(sourcepath): sourcepath}

            for i, relfilepath in enumerate(filepaths): # each file
                print(f"+sending {relfilepath} {i+1}/{len(filepaths)}")
                absfilepath = filepaths[relfilepath]

                fileid = uuid.uuid4().hex

                with open(absfilepath, "rb") as f:
                    filecontent = f.read()
                filehash = hashlib.md5(filecontent).hexdigest()
                filechunks = to_chunks(filecontent, 1024 * 512)  # 512KB each
                total_chunks = len(filechunks)

                publish_json_message(client, TRANS_TOPIC, {
                    "type": "transreq",
                    "fileid": fileid,
                    "relfilepath": relfilepath,
                    "len": total_chunks,
                    "md5": filehash,
                    "from": SENDER_ADDR,
                    "to": args.to
                })

                pending_req_confirm.append(fileid)

                while fileid in pending_req_confirm:
                    await asyncio.sleep(0.1)

                filestatus[fileid] = {
                    "remainchunk": {i: filechunks[i] for i in range(1, total_chunks + 1)},
                    "lastreact": time.time()
                }

                for i in range(1, total_chunks + 1):
                    publish_json_message(client, TRANS_TOPIC, {
                        "type": "trans",
                        "fileid": fileid,
                        "chunk": i,
                        "content": filechunks[i],
                        "from": SENDER_ADDR,
                        "to": args.to
                    })
                    print(f"+sent: {i}")
                    await asyncio.sleep(0.05)
                
                await monitor_chunks(fileid, cooldown=10)
        elif args.receive:
            global RECEIVER_ADDR
            RECEIVER_ADDR = uuid.uuid4().hex
            print(f"Receiver addr: {RECEIVER_ADDR}")

            while True:
                await asyncio.sleep(0.1)
        else:
            print("No role specified. Use --send or --receive.")
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting...")
