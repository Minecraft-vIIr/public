import os
import sys
import time
import uuid
import json
import hashlib
import base64
import asyncio
import argparse
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ------------------------ 公共工具函數 ------------------------

def exec_path():
    if getattr(sys, "frozen", False):
        application_path = sys.executable
    elif __file__:
        application_path = os.path.abspath(__file__)
    return application_path

def encrypt_message(message, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    return base64.b64encode(iv + encrypted).decode("utf-8")

def decrypt_message(encrypted_message, key):
    try:
        data = base64.b64decode(encrypted_message)
        iv = data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)
        return decrypted.decode("utf-8")
    except Exception:
        return None

def publish_json_message(client, topic, json_message):
    """
    將消息字典轉換為 JSON 字符串，使用 AES 加密後發布到指定的 MQTT topic。
    """
    msg = json.dumps(json_message)
    encrypted = encrypt_message(msg, AES_KEY)
    client.publish(topic, encrypted)

# MQTT 服務器與 topic 配置
BROKER = "mqtt.eclipseprojects.io"
PORT = 1883
TRANS_TOPIC = "FCTRL6/file/trans"  # 文件傳輸主題
CTRL_TOPIC  = "FCTRL6/file/ctrl"   # 控制確認主題

# ------------------------ 命令行參數解析 ------------------------

parser = argparse.ArgumentParser(description="MQTT File Transfer Tool")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--send", "-m", action="store_true", help="Act as sender")
group.add_argument("--receive", "-r", action="store_true", help="Act as receiver")
parser.add_argument("--input", "-i", help="Input file (required for send mode)")
parser.add_argument("--to", "-t", help="Target receiver's ID (required for send mode)")
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

# ------------------------ 發送端實現 ------------------------

if args.send:
    SENDER_ID = uuid.uuid4().hex
    TARGET_RECEIVER_ID = args.to
    # 保存發送端狀態
    sender_userdata = {"connected": False, "start_confirmed": False, "fileid": None, "sender_id": SENDER_ID}
    # 用於追蹤尚未確認的 chunk
    # 結構：{ fileid: {"remainchunk": {chunk: content, ...}, "lastreact": timestamp } }
    chunk_confirm_wait = {}

    def sender_on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Sender connected successfully")
            userdata["connected"] = True
            client.subscribe(CTRL_TOPIC)
        else:
            print("Sender connection failed with code", rc)

    def sender_on_message(client, userdata, msg):
        decrypted = decrypt_message(msg.payload.decode("utf-8"), AES_KEY)
        if not decrypted:
            print("Sender failed to decrypt a control message")
            return
        message = json.loads(decrypted)
        # 僅處理 receiver_id 為本發送端的消息
        if message.get("receiver_id") != SENDER_ID:
            return
        msg_type = message.get("type")
        if msg_type == "starttrans" and message.get("fileid") == userdata.get("fileid"):
            userdata["start_confirmed"] = True
            print("Received starttrans confirmation")
        elif msg_type == "recvchunk":
            fid = message.get("fileid")
            chunk = message.get("chunk")
            if fid == userdata.get("fileid") and fid in chunk_confirm_wait and chunk in chunk_confirm_wait[fid]["remainchunk"]:
                print(f"[?+] {chunk}")
                del chunk_confirm_wait[fid]["remainchunk"][chunk]
                chunk_confirm_wait[fid]["lastreact"] = time.time()

    def to_chunks(content, chunksize):
        chunks = {}
        for i, chunk in enumerate((content[i:i+chunksize] for i in range(0, len(content), chunksize)), start=1):
            chunks[i] = base64.b64encode(chunk).decode("utf-8")
        return chunks

    async def monitor_chunks(fileid, cooldown=10):
        chunk_confirm_wait[fileid]["lastreact"] = time.time()
        while chunk_confirm_wait[fileid]["remainchunk"]:
            await asyncio.sleep(0.5)
            if time.time() - chunk_confirm_wait[fileid]["lastreact"] >= cooldown:
                unconfirmed = list(chunk_confirm_wait[fileid]["remainchunk"].keys())
                print("No new confirmation in", cooldown, "seconds. Resending unconfirmed chunks:", unconfirmed)
                for chunk_id, content in list(chunk_confirm_wait[fileid]["remainchunk"].items()):
                    publish_json_message(sender_client, TRANS_TOPIC, {
                        "type": "trans",
                        "fileid": sender_userdata["fileid"],
                        "chunk": chunk_id,
                        "content": content,
                        "sender_id": SENDER_ID,
                        "receiver_id": TARGET_RECEIVER_ID
                    })
                chunk_confirm_wait[fileid]["lastreact"] = time.time()
        print("All chunks confirmed.")

    async def main_sender():
        # 生成文件傳輸的唯一標識
        current_fileid = uuid.uuid4().hex
        sender_userdata["fileid"] = current_fileid

        global sender_client
        sender_client = mqtt.Client(client_id=uuid.uuid4().hex, userdata=sender_userdata)
        sender_client.on_connect = sender_on_connect
        sender_client.on_message = sender_on_message
        sender_client.connect(BROKER, PORT, 60)
        sender_client.loop_start()

        while not sender_userdata["connected"]:
            await asyncio.sleep(0.1)

        filepath = args.input.strip('"')
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            filecontent = f.read()
        filehash = hashlib.md5(filecontent).hexdigest()
        filechunks = to_chunks(filecontent, 1024 * 512)  # 每塊 512KB
        total_chunks = len(filechunks)
        print(f"Sending file {filename} in {total_chunks} chunks")

        # 發送 transreq 消息，包含文件基本信息
        publish_json_message(sender_client, TRANS_TOPIC, {
            "type": "transreq",
            "fileid": current_fileid,
            "filename": filename,
            "len": total_chunks,
            "md5": filehash,
            "sender_id": SENDER_ID,
            "receiver_id": TARGET_RECEIVER_ID
        })

        # 等待接收端回覆 starttrans 消息
        while not sender_userdata["start_confirmed"]:
            await asyncio.sleep(0.1)

        chunk_confirm_wait[current_fileid] = {
            "remainchunk": {i: filechunks[i] for i in range(1, total_chunks + 1)},
            "lastreact": time.time()
        }

        # 依次發送每個 chunk
        for i in range(1, total_chunks + 1):
            publish_json_message(sender_client, TRANS_TOPIC, {
                "type": "trans",
                "fileid": current_fileid,
                "chunk": i,
                "content": filechunks[i],
                "sender_id": SENDER_ID,
                "receiver_id": TARGET_RECEIVER_ID
            })
            print(f"[+] {i}")
            await asyncio.sleep(0.05)

        await monitor_chunks(current_fileid, cooldown=10)
        await asyncio.sleep(2)
        sender_client.loop_stop()
        sender_client.disconnect()
        print("Sender finished.")

# ------------------------ 接收端實現 ------------------------

if args.receive:
    RECEIVER_ID = uuid.uuid4().hex
    print("Receiver ID:", RECEIVER_ID)
    receiver_userdata = {"connected": False}
    # 根據 fileid 保存文件信息與已接收的 chunk
    file_temp = {}

    def receiver_on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Receiver connected successfully")
            userdata["connected"] = True
            client.subscribe(TRANS_TOPIC)
        else:
            print("Receiver connection failed with code", rc)

    def receiver_on_message(client, userdata, msg):
        decrypted = decrypt_message(msg.payload.decode("utf-8"), AES_KEY)
        if not decrypted:
            print("Receiver failed to decrypt a message")
            return
        message = json.loads(decrypted)
        # 僅處理發送給本接收端的消息
        if message.get("receiver_id") != RECEIVER_ID:
            return
        msg_type = message.get("type")
        if msg_type == "transreq":
            fid = message.get("fileid")
            file_temp[fid] = {
                "filename": message.get("filename"),
                "md5": message.get("md5"),
                "len": message.get("len"),
                "chunks": {}
            }
            print(f"Received transreq for file {file_temp[fid]['filename']}")
            publish_json_message(receiver_client, CTRL_TOPIC, {
                "type": "starttrans",
                "fileid": fid,
                "sender_id": RECEIVER_ID,
                "receiver_id": message.get("sender_id")
            })
        elif msg_type == "trans":
            fid = message.get("fileid")
            if fid in file_temp:
                chunk_id = message.get("chunk")
                content = message.get("content")
                file_temp[fid]["chunks"][chunk_id] = content
                print(f"[+] {chunk_id}=>{file_temp[fid]['filename']}")
                publish_json_message(receiver_client, CTRL_TOPIC, {
                    "type": "recvchunk",
                    "fileid": fid,
                    "chunk": chunk_id,
                    "sender_id": RECEIVER_ID,
                    "receiver_id": message.get("sender_id")
                })
                # 若所有 chunk 均收到，則合併保存文件
                if len(file_temp[fid]["chunks"]) == file_temp[fid]["len"]:
                    save_dir = os.path.abspath(args.output)
                    os.makedirs(save_dir, exist_ok=True)
                    save_path = os.path.join(save_dir, file_temp[fid]["filename"])
                    with open(save_path, "wb") as f:
                        for i in range(1, file_temp[fid]["len"] + 1):
                            f.write(base64.b64decode(file_temp[fid]["chunks"][i].encode()))
                    print(f"Saved file to {save_path}")
                    del file_temp[fid]

    async def main_receiver():
        global receiver_client
        receiver_client = mqtt.Client(client_id=uuid.uuid4().hex, userdata=receiver_userdata)
        receiver_client.on_connect = receiver_on_connect
        receiver_client.on_message = receiver_on_message
        receiver_client.connect(BROKER, PORT, 60)
        receiver_client.loop_start()

        while not receiver_userdata["connected"]:
            await asyncio.sleep(0.1)
        print("Receiver is running. Waiting for files...")
        try:
            while True:
                await asyncio.sleep(0.1)
        except KeyboardInterrupt:
            print("Receiver exiting...")
        finally:
            receiver_client.loop_stop()
            receiver_client.disconnect()

# ------------------------ 主函數 ------------------------

async def main():
    tasks = []
    if args.send:
        tasks.append(asyncio.create_task(main_sender()))
    if args.receive:
        tasks.append(asyncio.create_task(main_receiver()))
    if tasks:
        await asyncio.gather(*tasks)
    else:
        print("No role specified. Use --send or --receive.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting program.")
