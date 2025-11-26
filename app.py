from flask import Flask, request, jsonify
import json
import threading
import requests
from byte import Encrypt_ID, encrypt_api
from spam_count_pb2 import Info
import httpx
import time
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import data_pb2
import encode_id_clan_pb2
import reqClan_pb2
import jwt as pyjwt
import os
import asyncio
import aiohttp

app = Flask(__name__)

freefire_version = "OB51"
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
JWT_REGEX = re.compile(r'(eyJ[A-Za-z0-9_\-\.=]+)')

def load_tokens(server_name):
    try:
        server_name = server_name.upper()
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        elif server_name == "EU":
            with open("token_eu.json", "r") as f:
                tokens = json.load(f)
        elif server_name == "VN":
            with open("token_vn.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        print(f"Error loading tokens for {server_name}: {e}")
        return None

def get_tokens_for_region(region):
    region = region.upper()
    
    token_filename = f"token_{region.lower()}.json"
    account_filename = f"account_{region.lower()}.json"
    
    tokens = []
    
    if os.path.exists(token_filename):
        try:
            with open(token_filename, "r") as f:
                tokens = json.load(f)
        except Exception as e:
            pass
    
    if not tokens and os.path.exists(account_filename):
        try:
            with open(account_filename, "r") as f:
                accounts = json.load(f)
            
            for account in accounts:
                uid = account.get("uid")
                password = account.get("password")
                if uid and password:
                    token = get_jwt_token_from_api(uid, password)
                    if token:
                        tokens.append({
                            "uid": uid,
                            "token": token
                        })
                    time.sleep(1)
            
            if tokens:
                with open(token_filename, "w") as f:
                    json.dump(tokens, f, indent=2)
                
        except Exception as e:
            pass
    
    return tokens

def get_jwt_token_from_api(uid, password):
    data_param = f"{uid}:{password}"
    url = f"https://api.freefireservice.dnc.su/oauth/account:login?data={data_param}"
    
    try:
        response = httpx.get(url, timeout=15.0)
        token_candidate = None
        
        try:
            j = response.json()
            for k in ("token", "jwt", "access_token", "data", "auth"):
                v = j.get(k)
                if isinstance(v, str) and v.startswith("ey"):
                    token_candidate = v
                    break
        except Exception:
            pass
        
        if not token_candidate:
            m = JWT_REGEX.search(response.text)
            if m:
                token_candidate = m.group(1)
        
        if not token_candidate:
            for hv in response.headers.values():
                m = JWT_REGEX.search(hv)
                if m:
                    token_candidate = m.group(1)
                    break
        
        return token_candidate
            
    except Exception as e:
        return None

def get_region_from_jwt(jwt_token):
    try:
        decoded = pyjwt.decode(jwt_token, options={"verify_signature": False})
        lock_region = decoded.get('lock_region', 'IND')
        return lock_region.upper()
    except Exception as e:
        return 'IND'

def get_request_url(server_name):
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/RequestAddingFriend"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/RequestAddingFriend"
    else:
        return "https://clientbp.ggblueshark.com/RequestAddingFriend"

def get_personal_show_url(server_name):
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        return "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

def get_region_url(region):
    region = region.upper()
    if region == "IND":
        return "https://client.ind.freefiremobile.com"
    elif region in ["BR", "US", "SAC", "NA"]:
        return "https://client.us.freefiremobile.com/"
    else:
        return "https://clientbp.ggblueshark.com/"

def parse_protobuf_response(response_data):
    try:
        info = Info()
        info.ParseFromString(response_data)
        return {
            "uid": info.AccountInfo.UID,
            "nickname": info.AccountInfo.PlayerNickname,
            "likes": info.AccountInfo.Likes,
            "region": info.AccountInfo.PlayerRegion,
            "level": info.AccountInfo.Levels
        }
    except Exception as e:
        print(f"❌ Protobuf parsing error: {e}")
        return None

def get_player_info(uid, token, url):
    try:
        encrypted = encrypt_api("08" + Encrypt_ID(str(uid)) + "1801")
        headers = {
            "Authorization": f"Bearer {token}",
            "ReleaseVersion": "OB51",
            "X-GA": "v1 1",
            "Host": url.replace("https://", "").split("/")[0],
        }
        resp = requests.post(url, headers=headers, data=bytes.fromhex(encrypted), verify=False, timeout=10)
        if resp.status_code == 200:
            return parse_protobuf_response(resp.content)
    except Exception as e:
        print(f"GetPlayerPersonalShow error: {e}")
    return None

def send_friend_request(uid, token, url, results):
    encrypted_id = Encrypt_ID(uid)
    payload = f"08a7c4839f1e10{encrypted_id}1801"
    encrypted_payload = encrypt_api(payload)

    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2022.3.47f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB51",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "16",
        "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br"
    }

    try:
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=10)
        if response.status_code == 200:
            results["success"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        print(f"Request error: {e}")
        results["failed"] += 1

def create_join_payload(clan_id):
    message = reqClan_pb2.MyMessage()
    message.field_1 = int(clan_id)
    serialized_data = message.SerializeToString()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(serialized_data, AES.block_size))
    return encrypted_data

def get_clan_info(base_url, jwt_token, clan_id):
    try:
        json_data = json.dumps({"1": int(clan_id), "2": 1})
        my_data = encode_id_clan_pb2.MyData()
        json_obj = json.loads(json_data)
        my_data.field1 = json_obj["1"]
        my_data.field2 = json_obj["2"]

        data_bytes = my_data.SerializeToString()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_info_data = cipher.encrypt(pad(data_bytes, 16))

        info_url = f"{base_url}/GetClanInfoByClanID"
        
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": freefire_version,
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
            "Host": base_url.replace("https://", ""),
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }

        with httpx.Client(timeout=30.0) as client_info:
            info_response = client_info.post(info_url, headers=headers, content=encrypted_info_data)
        
        if info_response.status_code == 200:
            resp_info = data_pb2.response()
            resp_info.ParseFromString(info_response.content)
            return {
                "clan_name": getattr(resp_info, "special_code", "Unknown"),
                "clan_level": getattr(resp_info, "level", "Unknown")
            }
        else:
            return {"clan_name": "Unknown", "clan_level": "Unknown"}
    except Exception as e:
        return {"clan_name": "Unknown", "clan_level": "Unknown"}

async def send_single_join_request(session, base_url, token, encrypted_data, uid):
    try:
        url = f"{base_url}/RequestJoinClan"
        host = base_url.replace("https://", "")

        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": freefire_version,
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
            "Host": host,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }

        async with session.post(url, headers=headers, data=encrypted_data, timeout=30.0) as response:
            status_code = response.status
            if status_code == 200:
                return {"uid": uid, "status": "success", "status_code": status_code}
            else:
                return {"uid": uid, "status": "failed", "status_code": status_code}
                
    except asyncio.TimeoutError:
        return {"uid": uid, "status": "failed", "status_code": 408}
    except Exception as e:
        return {"uid": uid, "status": "failed", "status_code": 500}

async def send_bulk_join_requests(clan_id, region, tokens):
    base_url = get_region_url(region)
    encrypted_data = create_join_payload(clan_id)
    
    results = []
    successful_requests = 0
    failed_requests = 0
    
    connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for account_data in tokens:
            token = account_data.get("token")
            uid = account_data.get("uid")
            
            if not token:
                continue
                
            token_region = get_region_from_jwt(token)
            if token_region != region:
                continue
            
            task = send_single_join_request(session, base_url, token, encrypted_data, uid)
            tasks.append(task)
            
            await asyncio.sleep(0.1)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if isinstance(result, Exception):
            failed_requests += 1
            continue
            
        if result.get("status") == "success":
            successful_requests += 1
        else:
            failed_requests += 1
    
    return results, successful_requests, failed_requests

@app.route("/send_request", methods=["GET"])
def handle_friend_request():
    uid = request.args.get("uid")
    server_name = request.args.get("server", "").upper()

    if not uid or not server_name:
        return jsonify({"error": "uid and server parameters are required"}), 400

    tokens = load_tokens(server_name)
    if not tokens:
        return jsonify({"error": f"No tokens found for region {server_name}"}), 500

    url = get_request_url(server_name)
    personal_show_url = get_personal_show_url(server_name)

    player_info = None
    for t in tokens:
        token = t["token"]
        player_info = get_player_info(uid, token, personal_show_url)
        if player_info:
            break

    results = {"success": 0, "failed": 0}
    threads = []

    for i in range(min(100, len(tokens))):
        token = tokens[i]["token"]
        thread = threading.Thread(target=send_friend_request, args=(uid, token, url, results))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    response = {
        "Credit": "g",
        "UID": uid,
        "Region": server_name,
        "Success": results["success"],
        "Failed": results["failed"],
        "Status": 1 if results["success"] > 0 else 2
    }

    if player_info:
        response.update({
            "Level": player_info.get("level", 0),
            "Likes": player_info.get("likes", 0),
            "Nickname": player_info.get("nickname", "")
        })

    return jsonify(response)

@app.route('/spam_clan', methods=['GET'])
def spam_clan():
    clan_id = request.args.get('id')
    region = request.args.get('region', 'IND').upper()
    
    if not clan_id:
        return jsonify({
            "error": "clan_id is required"
        }), 400
    
    valid_regions = ['IND', 'BR', 'US', 'SAC', 'NA', 'BD']
    if region not in valid_regions:
        return jsonify({
            "error": f"Invalid region"
        }), 400
    
    try:
        tokens = get_tokens_for_region(region)
        
        if not tokens:
            return jsonify({
                "error": f"No tokens found for region {region}"
            }), 400
        
        start_time = time.time()
        results, successful_requests, failed_requests = asyncio.run(
            send_bulk_join_requests(clan_id, region, tokens)
        )
        end_time = time.time()
        
        clan_info = {"clan_name": "Unknown", "clan_level": "Unknown"}
        for account_data in tokens:
            try:
                token = account_data.get("token")
                if token:
                    base_url = get_region_url(region)
                    clan_info = get_clan_info(base_url, token, clan_id)
                    break
            except:
                pass
        
        total_requests = len(tokens)
        
        response_data = {
            "clan_id": clan_id,
            "clan_name": clan_info.get("clan_name", "Unknown"),
            "region": region,
            "success": successful_requests,
            "failed": failed_requests,
            "total": total_requests,
            "take_time": f"{end_time - start_time:.2f}s"
        }
        
        return jsonify(response_data)

    except Exception as e:
        return jsonify({
            "error": "Server error"
        }), 500
# ==== Main ====
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
