import asyncio
import aiohttp
import requests
import json
import time
import threading
import random
import binascii
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

# Protobuf imports (Must exist in same directory)
import like_pb2
import like_count_pb2
import uid_generator_pb2

# --- CONFIGURATION ---
CLIENT_VERSION      = "1.120.1"
UNITY_VERSION       = "2018.4.11f1"
RELEASE_VERSION     = "OB52"
MSDK_VERSION        = "5.5.2P3"
USER_AGENT_MODEL    = "ASUS_Z01QD"
ANDROID_OS_VER      = "Android 10"
TOKEN_REFRESH_INTERVAL = 3000

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONSTANTS ---
REGION_LANG = {"ME": "ar","IND": "hi","ID": "id","VN": "vi","TH": "th","BD": "bn","PK": "ur","TW": "zh","CIS": "ru","SAC": "es","BR": "pt","SG": "en","NA": "en"}
LOGIN_HEX_KEY = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
LOGIN_CLIENT_KEY = bytes.fromhex(LOGIN_HEX_KEY)

class CryptoUtils:
    KEY = b'Yg&tc%DEuh6%Zc^8'
    IV = b'6oyZDr22E3ychjM%'

    @staticmethod
    def encrypt(plaintext):
        cipher = AES.new(CryptoUtils.KEY, AES.MODE_CBC, CryptoUtils.IV)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')

    @staticmethod
    def encrypt_login_api(plain_text):
        try:
            plain_bytes = bytes.fromhex(plain_text)
            key_bytes = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
            iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            return cipher.encrypt(pad(plain_bytes, AES.block_size)).hex()
        except Exception as e:
            print(f"[Login-Enc] Error: {e}")
            return None

class AccountManager:
    def __init__(self):
        self.accounts_cache = {}
        self.server_lists = {}
        self.lock = threading.Lock()
        
    def load_accounts(self, server_name):
        # Determine filename based on server
        if server_name == "IND":
            filename = "Accounts.ind.json"
        elif server_name in ["BR", "US", "SAC", "NA"]:
            filename = "Accounts.br.json"
        else:
            # Default to BD for BD, SG, others if not specified
            filename = "Accounts.bd.json"

        if not os.path.exists(filename):
            return 0

        try:
            with open(filename, "r") as f:
                data = json.load(f)
                with self.lock:
                    self.server_lists[server_name] = []
                    valid_count = 0
                    for acc in data:
                        uid = str(acc.get("uid"))
                        pwd = acc.get("password")
                        if uid and pwd:
                            if uid not in self.accounts_cache:
                                self.accounts_cache[uid] = {"password": pwd, "token": None, "token_time": 0}
                            self.server_lists[server_name].append(uid)
                            valid_count += 1
            return valid_count
        except Exception as e:
            print(f"Error loading file {filename}: {e}")
            return 0

    def perform_login(self, uid, password, region):
        try:
            ua_login = f"GarenaMSDK/{MSDK_VERSION}({USER_AGENT_MODEL};{ANDROID_OS_VER};en;US;)"
            url_grant = "https://100067.connect.garena.com/oauth/guest/token/grant"
            headers_grant = {"User-Agent": ua_login, "Content-Type": "application/x-www-form-urlencoded"}
            body_grant = {
                "uid": uid, "password": password, "response_type": "token", 
                "client_type": "2", "client_secret": LOGIN_CLIENT_KEY, "client_id": "100067"
            }
            
            resp_grant = requests.post(url_grant, headers=headers_grant, data=body_grant, timeout=20, verify=False)
            data_grant = resp_grant.json()

            if 'access_token' not in data_grant: return None
            access_token, open_id = data_grant['access_token'], data_grant['open_id']

            if region in ["ME", "TH"]: 
                url_login, host = "https://loginbp.common.ggbluefox.com/MajorLogin", "loginbp.common.ggbluefox.com"
            else: 
                url_login, host = "https://loginbp.ggblueshark.com/MajorLogin", "loginbp.ggblueshark.com"
            
            lang = REGION_LANG.get(region, "en")
            # Binary blob (Shortened for brevity, uses original logic)
            binary_head = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.120.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02'
            binary_tail = b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019119621\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
            
            full_payload = binary_head + lang.encode("ascii") + binary_tail
            temp_data = full_payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
            temp_data = temp_data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
            
            final_body = bytes.fromhex(CryptoUtils.encrypt_login_api(temp_data.hex()))
            
            headers_login = {
                "User-Agent": f"Dalvik/2.1.0 (Linux; U; {ANDROID_OS_VER}; {USER_AGENT_MODEL} Build/PI)", 
                "Content-Type": "application/x-www-form-urlencoded", "Host": host, "X-GA": "v1 1", "ReleaseVersion": RELEASE_VERSION
            }
            resp_login = requests.post(url_login, headers=headers_login, data=final_body, verify=False, timeout=30)
            
            if "eyJ" in resp_login.text:
                token = resp_login.text[resp_login.text.find("eyJ"):]
                end = token.find(".", token.find(".") + 1)
                return token[:end + 44] if end != -1 else token
            return None
        except Exception as e:
            print(f"[Login] Error: {e}")
            return None

    def get_token(self, uid, region):
        account = self.accounts_cache.get(str(uid))
        if not account: return None
        if account["token"] and (time.time() - account["token_time"] < TOKEN_REFRESH_INTERVAL):
            return account["token"]
        new_token = self.perform_login(uid, account["password"], region)
        if new_token:
            with self.lock:
                self.accounts_cache[uid]["token"] = new_token
                self.accounts_cache[uid]["token_time"] = time.time()
            return new_token
        return None

    def get_accounts(self, server_name):
        return self.server_lists.get(server_name, [])

# Initialize Global Manager
manager = AccountManager()

# --- PROTO HELPER ---
def create_like_payload(uid, region):
    message = like_pb2.like()
    message.uid = int(uid)
    message.region = region
    return message.SerializeToString()

# --- ASYNC LOGIC ---
async def send_single_like(session, url, encrypted_payload, uid, region):
    token = manager.get_token(uid, region)
    if not token: return False
    headers = {
        'User-Agent': f"Dalvik/2.1.0 (Linux; U; {ANDROID_OS_VER}; {USER_AGENT_MODEL} Build/PI)",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': UNITY_VERSION, 'X-GA': "v1 1", 'ReleaseVersion': RELEASE_VERSION
    }
    try:
        async with session.post(url, data=bytes.fromhex(encrypted_payload), headers=headers, timeout=10) as response:
            return response.status == 200
    except:
        return False

async def process_batch(target_uid, region, server_name, account_uids):
    if server_name == "IND": url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}: url = "https://client.us.freefiremobile.com/LikeProfile"
    else: url = "https://clientbp.ggblueshark.com/LikeProfile"

    payload = CryptoUtils.encrypt(create_like_payload(target_uid, region))
    
    async with aiohttp.ClientSession() as session:
        tasks = [send_single_like(session, url, payload, acc, server_name) for acc in account_uids]
        results = await asyncio.gather(*tasks)
        return results.count(True)

# --- PLAYER INFO ---
def get_player_info(target_uid, server_name):
    # Load accounts first to ensure we have a token
    manager.load_accounts(server_name)
    accts = manager.get_accounts(server_name)
    
    if not accts: return "No Accounts Found", 0
    
    # Try getting a valid token from first few accounts
    token = None
    for acc_uid in accts[:3]:
        token = manager.get_token(acc_uid, server_name)
        if token: break
    
    if not token: return "Token Error", 0

    if server_name == "IND": url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}: url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else: url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    try:
        msg = uid_generator_pb2.uid_generator()
        msg.krishna_ = int(target_uid)
        msg.teamXdarks = 1
        payload = CryptoUtils.encrypt(msg.SerializeToString())
        
        headers = {
            'User-Agent': f"Dalvik/2.1.0 (Linux; U; {ANDROID_OS_VER}; {USER_AGENT_MODEL} Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': UNITY_VERSION, 'X-GA': "v1 1", 'ReleaseVersion': RELEASE_VERSION
        }
        resp = requests.post(url, data=bytes.fromhex(payload), headers=headers, verify=False, timeout=10)
        
        if resp.status_code == 200:
            info = like_count_pb2.Info()
            info.ParseFromString(resp.content)
            return info.AccountInfo.PlayerNickname, info.AccountInfo.Likes
    except Exception as e:
        print(f"Info Error: {e}")
    return "Unknown", 0

# --- MAIN ENTRY POINT FOR BOT ---
def execute_likes(target_uid, server_name):
    # 1. Load Accounts
    count = manager.load_accounts(server_name)
    if count == 0:
        return {"success": False, "msg": f"❌ Server {server_name} এর জন্য কোনো অ্যাকাউন্ট ফাইল পাওয়া যায়নি।"}

    # 2. Get Info Before
    name, likes_before = get_player_info(target_uid, server_name)
    if name == "Token Error":
         return {"success": False, "msg": "❌ সার্ভার কানেকশন এরর (Token Failed)।"}

    # 3. Process Likes (Async wrapper)
    uids = manager.get_accounts(server_name)
    # Limit to 50 for safety or use all
    uids_to_use = uids[:50] 
    
    try:
        # Run Async in Sync
        likes_sent = asyncio.run(process_batch(target_uid, server_name, server_name, uids_to_use))
    except Exception as e:
        return {"success": False, "msg": f"❌ প্রসেসিং এরর: {str(e)}"}

    # 4. Get Info After
    _, likes_after = get_player_info(target_uid, server_name)

    return {
        "success": True,
        "name": name,
        "uid": target_uid,
        "before": likes_before,
        "after": likes_after,
        "sent": likes_sent,
        "total_acc": count
    }
