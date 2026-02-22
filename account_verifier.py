import os
import json
import base64
import struct
import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 1. CONFIGURATION & CONSTANTS
# ==========================================
class Config:
    AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    LOGIN_CLIENT_ID = "100067"
    LOGIN_HEX_KEY = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
    URL_GRANT = "https://100067.connect.garena.com/oauth/guest/token/grant"
    BINARY_HEAD = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.120.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02'
    BINARY_TAIL = b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019119621\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'

# ==========================================
# 2. CRYPTOGRAPHY ENGINE
# ==========================================
class CryptoEngine:
    @staticmethod
    def encrypt_aes(data_bytes):
        try:
            cipher = AES.new(Config.AES_KEY, AES.MODE_CBC, Config.AES_IV)
            return cipher.encrypt(pad(data_bytes, AES.block_size))
        except: return None

    @staticmethod
    def encrypt_hex_payload(hex_data):
        try:
            raw_bytes = bytes.fromhex(hex_data)
            encrypted = CryptoEngine.encrypt_aes(raw_bytes)
            return encrypted.hex()
        except: return None

    @staticmethod
    def encode_uid_for_proto(uid):
        try:
            val = int(uid)
            result = []
            while True:
                byte = val & 0x7F
                val >>= 7
                if val: byte |= 0x80
                result.append(byte)
                if not val: break
            return bytes(result).hex()
        except: return None

    @staticmethod
    def decode_jwt(token):
        try:
            parts = token.split('.')
            payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
            data = json.loads(base64.urlsafe_b64decode(payload))
            return str(data.get('account_id') or data.get('external_id'))
        except: return None

# ==========================================
# 3. PROTOBUF PARSER
# ==========================================
class SimpleProtoParser:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def parse(self):
        result = {}
        length = len(self.data)
        while self.pos < length:
            try:
                tag = self._read_varint()
                field_id = str(tag >> 3)
                wire_type = tag & 0x07
                value = None

                if wire_type == 0: value = self._read_varint()
                elif wire_type == 1: value = self._read_fixed64()
                elif wire_type == 2:
                    length_val = self._read_varint()
                    bytes_val = self.data[self.pos : self.pos + length_val]
                    self.pos += length_val
                    try:
                        sub_parser = SimpleProtoParser(bytes_val)
                        decoded_nested = sub_parser.parse()
                        if sub_parser.pos == len(bytes_val) and decoded_nested:
                            value = decoded_nested
                        else:
                            value = bytes_val.decode('utf-8', errors='ignore')
                    except:
                        value = bytes_val.decode('utf-8', errors='ignore')
                elif wire_type == 5: value = self._read_fixed32()

                if field_id not in result: 
                    result[field_id] = {"data": value}
            except: break
        return result

    def _read_varint(self):
        result = 0; shift = 0
        while True:
            if self.pos >= len(self.data): raise IndexError
            byte = self.data[self.pos]
            self.pos += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80): return result
            shift += 7

    def _read_fixed32(self):
        val = struct.unpack('<I', self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return val

    def _read_fixed64(self):
        val = struct.unpack('<Q', self.data[self.pos:self.pos+8])[0]
        self.pos += 8
        return val

# ==========================================
# 4. AUTH SERVICE (LOGIN LOGIC)
# ==========================================
class AuthService:
    @staticmethod
    def login(uid, password, region="BD"):
        try:
            headers = {"User-Agent": "GarenaMSDK/5.5.2P3(ASUS_I005DA;Android 9;en;US;)", "Content-Type": "application/x-www-form-urlencoded"}
            client_secret = bytes.fromhex(Config.LOGIN_HEX_KEY)
            
            body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": client_secret, "client_id": Config.LOGIN_CLIENT_ID}
            resp = requests.post(Config.URL_GRANT, headers=headers, data=body, timeout=20, verify=False)
            data = resp.json()

            if 'access_token' not in data:
                return {"success": False, "message": "Invalid UID or Password!"}

            access_token, open_id = data['access_token'], data['open_id']

            if region in ["ME", "TH"]: 
                url, host = "https://loginbp.common.ggbluefox.com/MajorLogin", "loginbp.common.ggbluefox.com"
            else: 
                url, host = "https://loginbp.ggblueshark.com/MajorLogin", "loginbp.ggblueshark.com"
            
            full_payload = Config.BINARY_HEAD + b"bn" + Config.BINARY_TAIL 
            temp_data = full_payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
            temp_data = temp_data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
            
            encrypted_body = CryptoEngine.encrypt_aes(temp_data).hex()
            final_body = bytes.fromhex(encrypted_body)

            headers_bp = {"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)", "Content-Type": "application/x-www-form-urlencoded", "Host": host, "X-GA": "v1 1", "ReleaseVersion": "OB52"}
            resp_bp = requests.post(url, headers=headers_bp, data=final_body, verify=False, timeout=30)
            
            if "eyJ" in resp_bp.text:
                token_start = resp_bp.text.find("eyJ")
                token_raw = resp_bp.text[token_start:]
                end = token_raw.find(".", token_raw.find(".") + 1)
                final_token = token_raw[:end + 44] if end != -1 else token_raw
                return {"success": True, "token": final_token}
            else:
                return {"success": False, "message": "Token Generation Failed! Server might be busy."}
        except Exception as e:
            return {"success": False, "message": f"Login Error: {str(e)}"}

# ==========================================
# 5. INFO FETCHER SERVICE
# ==========================================
class InfoService:
    @staticmethod
    def fetch_player_info(uid, token, server_name):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 10; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            'Authorization': f'Bearer {token}'
        }

        if server_name == "IND": url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in ["BR", "US", "SAC", "NA"]: url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in ["ME", "TH"]: url = "https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow"
        else: url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        try:
            encoded_uid = CryptoEngine.encode_uid_for_proto(uid)
            if not encoded_uid: return None

            raw_hex = f"08{encoded_uid}1007"
            encrypted_data = CryptoEngine.encrypt_hex_payload(raw_hex)
            
            response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_data), verify=False, timeout=15)

            if response.status_code == 200:
                parser = SimpleProtoParser(response.content)
                return parser.parse()
            else:
                return None
        except: return None

# ==========================================
# 6. MAIN VERIFICATION LOGIC
# ==========================================
def check_and_save_account(uid, password, server_name):
    try:
        # File mapping
        file_map = {"IND": "Accounts.ind.json", "BR": "Accounts.br.json", "US": "Accounts.br.json", "SAC": "Accounts.br.json", "NA": "Accounts.br.json"}
        filename = file_map.get(server_name, "Accounts.bd.json")
        
        accounts = []
        # 1. Duplicate Check
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f: 
                    accounts = json.load(f)
                for acc in accounts:
                    if str(acc.get("uid")) == str(uid):
                        return {"success": False, "msg": "❌ Account already submitted! Please provide a new account."}
            except: pass

        # 2. Login & Token Generation
        auth_result = AuthService.login(uid, password, server_name)
        if not auth_result["success"]:
            return {"success": False, "msg": f"❌ {auth_result['message']}"}

        token = auth_result["token"]

        # Extract Real UID from JWT Token (Critical for correct info)
        extracted_uid = CryptoEngine.decode_jwt(token)
        if not extracted_uid:
            extracted_uid = uid

        # 3. Fetch Player Info
        raw_data = InfoService.fetch_player_info(extracted_uid, token, server_name)
        if not raw_data:
             return {"success": False, "msg": "❌ Failed to fetch player info (Server Error/Banned)"}

        # 4. Extract Level and Region safely
        def get_v(path, default="N/A"):
            c = raw_data
            try:
                for k in path: c = c[k]["data"]
                return c
            except: return default

        level = int(get_v(["1", "6"], 0))
        region_code = get_v(["1", "5"], "Unknown")

        if level < 8:
            return {"success": False, "msg": f"❌ Failed: Account Level is only {level}.\n🌍 Server: {region_code}\n⚠️ Minimum Level 8 is required!"}

        # 5. Save to File
        accounts.append({"uid": str(uid), "password": str(password)})
        with open(filename, 'w') as f:
            json.dump(accounts, f, indent=2)
            
        return {"success": True, "msg": f"✅ Account successfully added to server!\n📊 Level: {level}\n🌍 Server: {region_code}", "level": level}

    except Exception as e:
        return {"success": False, "msg": f"❌ Internal Error: {str(e)}"}
