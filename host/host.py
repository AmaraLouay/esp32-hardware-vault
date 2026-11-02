import serial, time, sys, os, getpass

SERIAL_PORT = '/dev/ttyUSB0'
BAUD_RATE   = 115200
MAX_FILE    = 3072   #firmware

def read_reply(ser, prefixes, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if line and any(line.startswith(p) for p in prefixes):
            return line
    return None

def open_port():
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=2)
    time.sleep(2)
    ser.reset_input_buffer()
    return ser

def authenticate(ser):
    p = getpass.getpass("[*] Vault passphrase: ")
    ser.write(b"AUTH:" + p.encode() + b"\n")
    reply = read_reply(ser, ("UNLOCKED", "ERROR"))
    print("[*]", reply)
    return bool(reply and reply.startswith("UNLOCKED"))

def setpass():
    p = getpass.getpass("[*] Set a NEW vault passphrase: ")
    ser = open_port()
    ser.write(b"SETPASS:" + p.encode() + b"\n")
    print("[+]", read_reply(ser, ("OK:", "ERROR")))
    ser.close()

def encrypt_file(path):
    data = open(path, 'rb').read()
    if len(data) > MAX_FILE:
        print(f"[-] File is {len(data)} bytes; max is {MAX_FILE}."); return
    ser = open_port()
    if not authenticate(ser): ser.close(); return
    print(f"[*] Encrypting '{path}' ({len(data)} bytes)...")
    ser.write(b"ENCFILE:" + data.hex().encode() + b"\n")
    print("[+]", read_reply(ser, ("OK:", "ERROR")))
    ser.close()

def decrypt_file(out_path):
    ser = open_port()
    if not authenticate(ser): ser.close(); return
    ser.write(b"DEC\n")
    reply = read_reply(ser, ("PLAIN:", "ERROR"))
    ser.close()
    if not reply or not reply.startswith("PLAIN:"):
        print("[-]", reply); return
    data = bytes.fromhex(reply[len("PLAIN:"):])
    open(out_path, 'wb').write(data)
    print(f"[+] Decrypted {len(data)} bytes -> '{out_path}'")

def display():
    ser = open_port()
    if not authenticate(ser): ser.close(); return
    ser.write(b"DISPLAY\n")
    print("[!]", read_reply(ser, ("STORED:", "ERROR")))
    ser.close()

def delete():
    ser = open_port()
    if not authenticate(ser): ser.close(); return
    ser.write(b"DELETE\n")
    print("[+]", read_reply(ser, ("DELETED", "ERROR")))
    ser.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:\n  setpass\n  encrypt <file>\n  decrypt <outfile>\n  display\n  delete")
        sys.exit(1)
    cmd = sys.argv[1]
    if   cmd == "setpass": setpass()
    elif cmd == "encrypt" and len(sys.argv) == 3: encrypt_file(sys.argv[2])
    elif cmd == "decrypt" and len(sys.argv) == 3: decrypt_file(sys.argv[2])
    elif cmd == "display": display()
    elif cmd == "delete":  delete()
    else: print("Bad args. See usage.")