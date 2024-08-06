#!/usr/bin/python

import time
import base64
import hashlib
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import websocket
import json

api_key = "API-KEY" #Client Id
api_secret = "API-SECRET" # Client Secret

username = api_key
timestamp_in_ms = "1566966208786";
nonce64 = "bmPX5hxV0FmVu7ejPj7A3VisQlVltOpbr48h1Q+D8UQ="; # must be new each Logon
raw_data = timestamp_in_ms + "." + nonce64;
base_signature_string = raw_data + api_secret;
password = base64.b64encode(hashlib.sha256(base_signature_string.encode('ascii')).digest())
print("Username: " + username)
print("RawData: " + raw_data)
print("Password: " + password.decode('ascii'))

#random part of the nonce must not be repeated in subsequent request
#it is worth to double-check the timestamp before sending to server as it is stored on server. 

