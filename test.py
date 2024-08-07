import asyncio
import base64
import hashlib
import os
from datetime import datetime
import socket
import yaml

# Load API credentials from the YAML file
with open('setup.yml', 'r') as file:
    setup = yaml.safe_load(file)

api_key = setup["api_key"]
api_secret = setup["api_secret"]

def generate_credentials(api_key, api_secret):
    username = api_key
    timestamp_in_ms = datetime.now().strftime('%Y%m%d-%H:%M:%S.%f')[:-3]
    nonce64 = base64.b64encode(os.urandom(32)).decode('ascii')
    raw_data = timestamp_in_ms + "." + nonce64
    base_signature_string = raw_data + api_secret
    password = base64.b64encode(hashlib.sha256(base_signature_string.encode('ascii')).digest())
    return username, raw_data, password

async def send_fix_message():
    username, raw_data, password = generate_credentials(api_key, api_secret)

    print("Username: " + username)
    print("RawData: " + raw_data)
    print("Password: " + password.decode('ascii'))

    DERIBIT_HOST = "test.deribit.com"
    DERIBIT_PORT = 9881
    SOH = chr(1)

    body = "35=A" + SOH + "49=TestClient" + SOH + "56=DERIBITSERVER" + SOH + \
    "34=1" + SOH + "52=20240807-14:39:55.638" + SOH + "98=0" + SOH + "108=1" + SOH + \
    "96=" + raw_data + SOH + "553=" + username + SOH + "554=" + password.decode('ascii') + SOH

    buff = "8=FIX.4.4" + SOH + "9=" + str(len(body)) + SOH + body

    checksum = 0
    for i in range(len(buff)):
        checksum += ord(buff[i])
    checksum = str(checksum % 256).zfill(3)
    buff = buff + "10=" + checksum + SOH

    try:
        reader, writer = await asyncio.open_connection(DERIBIT_HOST, DERIBIT_PORT)

        writer.write(buff.encode('ascii'))
        await writer.drain()
        print("Sent: " + repr(buff))

        data = await reader.read(1024)
        await asyncio.sleep(2)
        print('Received: ', repr(data))
    except Exception as e:
        print("Exception: ", e)
    finally:
        writer.close()
        await writer.wait_closed()

async def main():
    retry_attempts = 3
    retry_delay = 2  # seconds

    for attempt in range(retry_attempts):
        print(f"Attempt: {attempt + 1}")
        await send_fix_message()
        await asyncio.sleep(retry_delay)

# Run the main function
asyncio.run(main())