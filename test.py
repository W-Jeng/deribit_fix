#!/usr/bin/python

import time
import base64
import hashlib
import os
from datetime import datetime
import socket
import yaml

with open('setup.yml', 'r') as file:
    setup = yaml.safe_load(file)

api_key = setup["api_key"] #Client Id
api_secret = setup["api_secret"] # Client Secret

username = api_key
timestamp_in_ms = datetime.now().strftime('%S') + "000";
nonce64 = base64.b64encode(os.urandom(32)).decode('ascii');
raw_data = timestamp_in_ms + "." + nonce64;
base_signature_string = raw_data + api_secret;
password = base64.b64encode(hashlib.sha256(base_signature_string.encode('ascii')).digest())
print("Username: " + username)
print("RawData: " + raw_data)
print("Password: " + password.decode('ascii'))

#random part of the nonce must not be repeated in subsequent request
#it is worth to double-check the timestamp before sending to server as it is stored on server. 


# tcp sending

DERIBIT_HOST = "test.deribit.com"
DERIBIT_PORT = 9881
SOH = chr(1)

# just to not code FIX timestamp, some date hardcoded
body = "35=A" + SOH + "49=TestClient" + SOH + "56=DERIBITSERVER" + SOH + \
"34=1" + SOH + "52=20240805-12:09:55.638" + SOH + "98=0" + SOH + "108=1" + SOH + \
"96=" + raw_data + SOH + "553=" + username + SOH + "554=" + password.decode('ascii') + SOH;

buff = "8=FIX.4.4" + SOH + "9=" + str(len(body)) + SOH + body;

checksum = 0
for i in range(1, len(body)):
    checksum += ord(body[i])
checksum = str(checksum % 256)

while(len(checksum) < 3): checksum = '0' + checksum
      
buff = buff + "10=" + checksum + SOH;

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((DERIBIT_HOST, DERIBIT_PORT))
s.sendall(buff.encode('ascii'))

print("Sent: " + repr(buff))

data = s.recv(1024)
print('Received: ', repr(data))
s.close()