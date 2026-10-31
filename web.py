#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from collections import deque
import json
import re
import os
import subprocess
import time
import socket
import ipaddress
import threading
import secrets
import hashlib
from functools import wraps
from urllib.request import Request, urlopen
from urllib.parse import quote

# 应用启动时间标识
APP_START_TIME = time.time()

# 路径配置
BASE_DIR = "/opt/tcpingmonitor"
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "monitor.log")
STATUS_FILE = os.path.join(BASE_DIR, "status.json")
LAST_ACTION_FILE = os.path.join(BASE_DIR, "last_action.json")
IP_CACHE_FILE = os.path.join(BASE_DIR, "ip_cache.json")
IP_CACHE_LOCK = threading.Lock()
IP_API_URL = "http://ip-api.com/json/"

app = Flask(__name__, template_folder="templates")

# Web 登录配置
SESSION_SECRET_FILE = os.path.join(BASE_DIR, ".session_secret")
DEFAULT_WEB_PASSWORD = "123456"

def load_session_secret():
    """读取或生成持久化 Session 密钥。"""
    try:
        if os.path.exists(SESSION_SECRET_FILE):
            with open(SESSION_SECRET_FILE, "r", encoding="utf-8") as f:
                value = f.read().strip()
                if len(value) >= 32:
                    return value

        value = secrets.token_hex(32)
        with open(SESSION_SECRET_FILE, "w", encoding="utf-8") as f:
            f.write(value)
        try:
            os.chmod(SESSION_SECRET_FILE, 0o640)
        except OSError:
            pass
        return value
    except Exception as e:
        print(f"[Auth] 无法保存 Session 密钥，使用临时密钥: {e}")
        return secrets.token_hex(32)

app.secret_key = os.environ.get("tcpingmonitor_SECRET_KEY") or load_session_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=86400,
)

def _password_hash(password, salt=None):
    """使用 PBKDF2-SHA256 保存密码，不保存明文。"""
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def _verify_password(password, encoded):
    try:
        scheme, iterations, salt_hex, digest_hex = str(encoded).split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def get_web_password():
    """兼容旧版：没有前端修改过密码时，从 systemd 环境变量读取初始密码。"""
    cfg = load_config()
    stored_hash = cfg.get("web_password_hash")
    if stored_hash:
        return stored_hash
    return os.environ.get("tcpingmonitor_PASSWORD", DEFAULT_WEB_PASSWORD)


def verify_web_password(password):
    value = get_web_password()
    if str(value).startswith("pbkdf2_sha256$"):
        return _verify_password(password, value)
    return secrets.compare_digest(password, str(value))


def change_web_password(new_password):
    cfg = load_config()
    cfg["web_password_hash"] = _password_hash(new_password)
    save_json_atomic(CONFIG_FILE, cfg)

def is_logged_in():
    return bool(session.get("authenticated"))

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if is_logged_in():
            return view(*args, **kwargs)

        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "未登录", "login_required": True}), 401

        return redirect(url_for("login"))
    return wrapped

@app.before_request
def require_login():
    # 登录页面、登录接口、静态资源不需要登录。
    if request.endpoint in {"login", "do_login"} or request.path.startswith("/static/"):
        return None

    if not is_logged_in():
        if request.path.startswith("/api/"):
            return jsonify({"ok": False, "error": "未登录", "login_required": True}), 401
        return redirect(url_for("login"))

    return None



# =====================
# 工具函数
# =====================

def write_log(msg):
    """向日志文件写入带有时间戳的操作日志（含权限自愈机制）"""
    try:
        log_dir = os.path.dirname(LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {msg}\n"

        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except PermissionError:
            # 遭遇 root 创建文件的权限锁定时，使用 sudo 强行修改日志文件权限为 666 (全员可读写)
            subprocess.run(["sudo", "chmod", "666", LOG_FILE], check=False)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_entry)
    except Exception as e:
        print(f"[Log Error] 写入日志失败: {e}")


def load_config():
    """读取配置文件"""
    default_cfg = {"nodes": [], "worker": "", "interval": 60}
    if not os.path.exists(CONFIG_FILE):
        return default_cfg

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            default_cfg.update(data)
            return default_cfg
    except Exception as e:
        print(f"[Config Error] 读取配置文件失败: {e}")
        return default_cfg


def save_json_atomic(filepath, data):
    """原子化写入 JSON 避免文件损坏"""
    temp_file = f"{filepath}.tmp"
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(temp_file, filepath)
    except Exception as e:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        raise e




def load_ip_cache():
    """读取 IP 归属地永久缓存。"""
    if not os.path.exists(IP_CACHE_FILE):
        return {}
    try:
        with open(IP_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[IP Cache Error] 读取缓存失败: {e}")
        return {}


def save_ip_cache(cache):
    """原子化保存 IP 归属地缓存。"""
    save_json_atomic(IP_CACHE_FILE, cache)


def normalize_lookup_target(target):
    """IP 直接使用；域名由服务器端 DNS 解析为一个可查询 IP。"""
    target = str(target or "").strip()
    if not target:
        return "", ""

    # 允许用户输入 [IPv6] 形式。
    candidate = target[1:-1] if target.startswith("[") and target.endswith("]") else target
    try:
        return target, str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        # 优先 IPv4，与大多数 VPS 节点录入习惯保持一致；没有 IPv4 再使用 IPv6。
        addresses = []
        for info in infos:
            addr = info[4][0]
            if addr not in addresses:
                addresses.append(addr)
        ipv4 = next((x for x in addresses if ":" not in x), None)
        resolved = ipv4 or (addresses[0] if addresses else "")
        return target, resolved
    except Exception:
        return target, ""



# 归属地中文映射（沿用原前端显示规则，迁移到后端）
COUNTRY_ZH = {
    "CN":"中国", "HK":"中国香港", "MO":"中国澳门", "TW":"中国台湾", "JP":"日本", "KR":"韩国", "SG":"新加坡", "US":"美国", "CA":"加拿大", "GB":"英国", "DE":"德国", "FR":"法国", "NL":"荷兰", "RU":"俄罗斯", "AU":"澳大利亚", "NZ":"新西兰", "IN":"印度", "MY":"马来西亚", "TH":"泰国", "VN":"越南", "ID":"印度尼西亚", "PH":"菲律宾", "AE":"阿联酋", "TR":"土耳其", "BR":"巴西", "AR":"阿根廷", "MX":"墨西哥", "IT":"意大利", "ES":"西班牙", "SE":"瑞典", "CH":"瑞士", "NO":"挪威", "FI":"芬兰", "DK":"丹麦", "PL":"波兰", "UA":"乌克兰", "IE":"爱尔兰", "AT":"奥地利", "BE":"比利时", "CZ":"捷克", "RO":"罗马尼亚", "ZA":"南非", "IL":"以色列", "PT":"葡萄牙", "GR":"希腊", "HU":"匈牙利", "BG":"保加利亚", "RS":"塞尔维亚", "SK":"斯洛伐克", "SI":"斯洛文尼亚", "HR":"克罗地亚", "LT":"立陶宛", "LV":"拉脱维亚", "EE":"爱沙尼亚", "IS":"冰岛", "LU":"卢森堡", "MT":"马耳他", "CY":"塞浦路斯", "GE":"格鲁吉亚", "AM":"亚美尼亚", "AZ":"阿塞拜疆", "KZ":"哈萨克斯坦", "UZ":"乌兹别克斯坦", "PK":"巴基斯坦", "BD":"孟加拉国", "LK":"斯里兰卡", "NP":"尼泊尔", "MM":"缅甸", "KH":"柬埔寨", "LA":"老挝", "MN":"蒙古", "SA":"沙特阿拉伯", "QA":"卡塔尔", "KW":"科威特", "OM":"阿曼", "BH":"巴林", "JO":"约旦", "LB":"黎巴嫩", "EG":"埃及", "MA":"摩洛哥", "DZ":"阿尔及利亚", "TN":"突尼斯", "KE":"肯尼亚", "NG":"尼日利亚", "GH":"加纳", "ET":"埃塞俄比亚", "CL":"智利", "PE":"秘鲁", "CO":"哥伦比亚", "VE":"委内瑞拉", "UY":"乌拉圭", "PY":"巴拉圭", "BO":"玻利维亚", "EC":"厄瓜多尔", "CR":"哥斯达黎加", "PA":"巴拿马", "DO":"多米尼加共和国", "GT":"危地马拉", "CU":"古巴", "JM":"牙买加", "PR":"波多黎各"
}

REGION_ZH = {
    # 日本
    "Tokyo":"东京", "Osaka":"大阪", "Kyoto":"京都", "Hokkaido":"北海道", "Aichi":"爱知县", "Kanagawa":"神奈川县", "Saitama":"埼玉县", "Chiba":"千叶县", "Fukuoka":"福冈县", "Hyogo":"兵库县",
    # 中国大陆
    "Guangdong":"广东省", "Jiangsu":"江苏省", "Zhejiang":"浙江省", "Beijing":"北京市", "Shanghai":"上海市", "Shandong":"山东省", "Fujian":"福建省", "Sichuan":"四川省", "Hubei":"湖北省", "Hunan":"湖南省", "Anhui":"安徽省", "Jiangxi":"江西省", "Henan":"河南省", "Hebei":"河北省", "Shanxi":"山西省", "Liaoning":"辽宁省", "Jilin":"吉林省", "Heilongjiang":"黑龙江省", "Shaanxi":"陕西省", "Gansu":"甘肃省", "Qinghai":"青海省", "Yunnan":"云南省", "Guizhou":"贵州省", "Guangxi":"广西壮族自治区", "Inner Mongolia":"内蒙古自治区", "Xinjiang":"新疆维吾尔自治区", "Tibet":"西藏自治区", "Ningxia":"宁夏回族自治区",
    # 港澳台
    "Hong Kong":"香港", "Macau":"澳门", "Taiwan":"台湾", "Kowloon":"九龙", "New Territories":"新界", "Kwai Tsing District":"葵青区", "Central and Western District":"中西区", "Eastern District":"东区", "Southern District":"南区", "Wan Chai District":"湾仔区", "Sham Shui Po District":"深水埗区", "Wong Tai Sin District":"黄大仙区", "Yau Tsim Mong District":"油尖旺区", "Kowloon City District":"九龙城区", "Kwun Tong District":"观塘区", "Sai Kung District":"西贡区", "Sha Tin District":"沙田区", "Tai Po District":"大埔区", "Tsuen Wan District":"荃湾区", "Tuen Mun District":"屯门区", "Yuen Long District":"元朗区", "North District":"北区", "Islands District":"离岛区",
    # 美国常见州
    "Alabama":"阿拉巴马州", "Alaska":"阿拉斯加州", "Arizona":"亚利桑那州", "Arkansas":"阿肯色州", "California":"加利福尼亚州", "Colorado":"科罗拉多州", "Connecticut":"康涅狄格州", "Delaware":"特拉华州", "Florida":"佛罗里达州", "Georgia":"佐治亚州", "Hawaii":"夏威夷州", "Idaho":"爱达荷州", "Illinois":"伊利诺伊州", "Indiana":"印第安纳州", "Iowa":"艾奥瓦州", "Kansas":"堪萨斯州", "Kentucky":"肯塔基州", "Louisiana":"路易斯安那州", "Maine":"缅因州", "Maryland":"马里兰州", "Massachusetts":"马萨诸塞州", "Michigan":"密歇根州", "Minnesota":"明尼苏达州", "Mississippi":"密西西比州", "Missouri":"密苏里州", "Montana":"蒙大拿州", "Nebraska":"内布拉斯加州", "Nevada":"内华达州", "New Hampshire":"新罕布什尔州", "New Jersey":"新泽西州", "New Mexico":"新墨西哥州", "New York":"纽约州", "North Carolina":"北卡罗来纳州", "North Dakota":"北达科他州", "Ohio":"俄亥俄州", "Oklahoma":"俄克拉何马州", "Oregon":"俄勒冈州", "Pennsylvania":"宾夕法尼亚州", "Rhode Island":"罗得岛州", "South Carolina":"南卡罗来纳州", "South Dakota":"南达科他州", "Tennessee":"田纳西州", "Texas":"得克萨斯州", "Utah":"犹他州", "Vermont":"佛蒙特州", "Virginia":"弗吉尼亚州", "Washington":"华盛顿州", "West Virginia":"西弗吉尼亚州", "Wisconsin":"威斯康星州", "Wyoming":"怀俄明州", "District of Columbia":"哥伦比亚特区",
    # 其他常见地区
    "Ontario":"安大略省", "Quebec":"魁北克省", "British Columbia":"不列颠哥伦比亚省", "England":"英格兰", "Scotland":"苏格兰", "Wales":"威尔士", "Bavaria":"巴伐利亚州", "Hesse":"黑森州", "Île-de-France":"法兰西岛大区", "Seoul":"首尔特别市", "Busan":"釜山广域市", "Gyeonggi":"京畿道", "Singapore":"新加坡"
}

CITY_ZH = {
    "Tokyo":"东京", "Osaka":"大阪", "Kyoto":"京都", "Nagoya":"名古屋", "Yokohama":"横滨", "Sapporo":"札幌", "Fukuoka":"福冈", "Kobe":"神户", "Hong Kong":"香港", "Macau":"澳门", "Taipei":"台北", "Kaohsiung":"高雄", "Beijing":"北京", "Shanghai":"上海", "Guangzhou":"广州", "Shenzhen":"深圳", "Nanjing":"南京", "Nanjing City":"南京", "Suzhou":"苏州", "Wuxi":"无锡", "Hangzhou":"杭州", "Ningbo":"宁波", "Wenzhou":"温州", "Hefei":"合肥", "Jinan":"济南", "Qingdao":"青岛", "Zhengzhou":"郑州", "Wuhan":"武汉", "Changsha":"长沙", "Nanchang":"南昌", "Fuzhou":"福州", "Xiamen":"厦门", "Chengdu":"成都", "Chongqing":"重庆", "Xi'an":"西安", "Xian":"西安", "Shenyang":"沈阳", "Dalian":"大连", "Harbin":"哈尔滨", "Changchun":"长春", "Kunming":"昆明", "Guiyang":"贵阳", "Nanning":"南宁", "Urumqi":"乌鲁木齐", "Lanzhou":"兰州", "Xining":"西宁", "Yinchuan":"银川", "Hohhot":"呼和浩特", "Los Angeles":"洛杉矶", "San Francisco":"旧金山", "New York":"纽约", "Chicago":"芝加哥", "Seattle":"西雅图", "Houston":"休斯顿", "Dallas":"达拉斯", "Miami":"迈阿密", "Boston":"波士顿", "Washington":"华盛顿", "Vancouver":"温哥华", "Toronto":"多伦多", "Montreal":"蒙特利尔", "London":"伦敦", "Manchester":"曼彻斯特", "Paris":"巴黎", "Frankfurt":"法兰克福", "Berlin":"柏林", "Amsterdam":"阿姆斯特丹", "Moscow":"莫斯科", "Sydney":"悉尼", "Melbourne":"墨尔本", "Singapore":"新加坡", "Seoul":"首尔", "Busan":"釜山", "Bangkok":"曼谷", "Kuala Lumpur":"吉隆坡", "Jakarta":"雅加达", "Manila":"马尼拉", "Dubai":"迪拜", "Istanbul":"伊斯坦布尔", "Madrid":"马德里", "Barcelona":"巴塞罗那", "Rome":"罗马", "Milan":"米兰", "Zurich":"苏黎世", "Vienna":"维也纳", "Prague":"布拉格", "Warsaw":"华沙", "Stockholm":"斯德哥尔摩", "Oslo":"奥斯陆", "Helsinki":"赫尔辛基", "Copenhagen":"哥本哈根", "Dublin":"都柏林", "Lisbon":"里斯本", "Athens":"雅典", "Salt Lake City":"盐湖城", "Kwai Chung":"葵涌", "Tsuen Wan":"荃湾", "Tsing Yi":"青衣", "Sha Tin":"沙田", "Tuen Mun":"屯门", "Yuen Long":"元朗", "Tai Po":"大埔", "Central":"中环", "Causeway Bay":"铜锣湾", "Mong Kok":"旺角", "Kowloon":"九龙"
}
IP_CACHE_VERSION = 4

def zh_location(value, mapping):
    value = str(value or "").strip()
    return mapping.get(value, value)

def format_ip_location(data):
    """智能中文归属地：翻译、行政层级去重、港澳台专项处理。"""
    country_code = str(data.get("countryCode") or "").strip().upper()
    country_raw = str(data.get("country") or "").strip()
    region_raw = str(data.get("regionName") or data.get("region") or "").strip()
    city_raw = str(data.get("city") or "").strip()

    country = COUNTRY_ZH.get(country_code, country_raw)
    region = zh_location(region_raw, REGION_ZH)
    city = zh_location(city_raw, CITY_ZH)

    # 规范化特殊地区显示。
    if country_code == "HK":
        country = "中国香港"
        # ip-api 常把 city 也返回 Hong Kong，避免“中国香港 香港/九龙 香港”这种重复。
        if city_raw.lower() in {"hong kong", "hongkong"} or city == "香港":
            city = ""
        if region in {"香港", "中国香港"}:
            region = ""
    elif country_code == "MO":
        country = "中国澳门"
        if city_raw.lower() in {"macau", "macao"} or city == "澳门":
            city = ""
        if region in {"澳门", "中国澳门"}:
            region = ""
    elif country_code == "TW":
        country = "中国台湾"
        if region in {"台湾", "中国台湾"}:
            region = ""

    # 通用去重：原始值或翻译值重复都只保留一次。
    parts = []
    for value in (country, region, city):
        value = str(value or "").strip()
        if value and value not in parts:
            parts.append(value)

    org = str(data.get("isp") or data.get("org") or data.get("asname") or "").strip()
    location = " ".join(parts)
    if org:
        location += (" · " if location else "") + org
    return location or "未知"

def query_ip_api(ip):
    params = "?fields=status,message,country,countryCode,region,regionName,city,isp,org,asname,query"
    url = IP_API_URL + quote(ip, safe="") + params
    req = Request(url, headers={"Accept": "application/json", "User-Agent": "tcpingmonitor/1.0"})
    with urlopen(req, timeout=8) as resp:
        if resp.status != 200:
            return None
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if not isinstance(data, dict) or data.get("status") != "success":
            return None
        return data


def get_last_action():
    if os.path.exists(LAST_ACTION_FILE):
        try:
            with open(LAST_ACTION_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("last_action", "无动作")
        except Exception:
            pass
    return "无动作"


def set_last_action(action_str):
    try:
        save_json_atomic(LAST_ACTION_FILE, {"last_action": action_str})
    except Exception as e:
        print(f"[Error] 保存上次指令状态失败: {e}")


# =====================
# 路由接口
# =====================

@app.route("/login", methods=["GET"])
def login():
    if is_logged_in():
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def do_login():
    data = request.get_json(silent=True) or request.form
    password = str(data.get("password", ""))
    if verify_web_password(password):
        session.clear()
        session["authenticated"] = True
        session.permanent = True
        return jsonify({"ok": True})

    return jsonify({"ok": False, "error": "密码错误"}), 401

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    if request.method == "POST":
        return jsonify({"ok": True})
    return redirect(url_for("login"))

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/config")
def api_config():
    cfg = load_config()
    # 密码哈希只保存在服务器端，绝不通过 API 返回到浏览器。
    cfg.pop("web_password_hash", None)
    return jsonify(cfg)


@app.route("/api/change-password", methods=["POST"])
def api_change_password():
    data = request.get_json(silent=True) or {}
    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))
    confirm_password = str(data.get("confirm_password", ""))

    if not current_password:
        return jsonify({"ok": False, "error": "请输入当前密码"}), 400
    if not verify_web_password(current_password):
        return jsonify({"ok": False, "error": "当前密码错误"}), 400
    if len(new_password) < 8:
        return jsonify({"ok": False, "error": "新密码至少 8 位"}), 400
    if new_password != confirm_password:
        return jsonify({"ok": False, "error": "两次输入的新密码不一致"}), 400
    if new_password == current_password:
        return jsonify({"ok": False, "error": "新密码不能与当前密码相同"}), 400

    try:
        change_web_password(new_password)
        write_log("Web 管理密码已修改")
        return jsonify({"ok": True, "message": "密码修改成功"})
    except Exception as e:
        print(f"[Auth] 修改 Web 密码失败: {e}")
        return jsonify({"ok": False, "error": "密码保存失败，请检查服务器权限"}), 500


@app.route("/api/add", methods=["POST"])
def add_node():
    try:
        data = request.get_json(silent=True) or {}
        ip = str(data.get("ip", "")).strip()
        name = str(data.get("name", "")).strip() or ip

        if not ip:
            write_log("添加节点失败: IP或域名不能为空")
            return jsonify({"ok": False, "msg": "IP或域名不能为空"})

        cfg = load_config()

        for n in cfg.get("nodes", []):
            if n.get("ip") == ip:
                write_log(f"添加节点失败: 节点 [{ip}] 已存在")
                return jsonify({"ok": False, "msg": "节点已存在"})

        icmp_enabled = bool(data.get("icmp_enabled", True))
        ports_raw = data.get("ports", "")
        ports = []
        if isinstance(ports_raw, str):
            candidates = re.split(r"[,，\s]+", ports_raw.strip())
        elif isinstance(ports_raw, list):
            candidates = ports_raw
        else:
            candidates = []
        for value in candidates:
            if str(value).strip():
                try:
                    port = int(value)
                    if not 1 <= port <= 65535:
                        raise ValueError
                    if port not in ports:
                        ports.append(port)
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "msg": f"无效端口：{value}，端口范围为 1-65535"})
        if not icmp_enabled and not ports:
            return jsonify({"ok": False, "msg": "请至少启用 ICMP Ping 或填写一个 TCP 端口"})
        cfg.setdefault("nodes", []).append({"name": name, "ip": ip,
            "icmp_enabled": icmp_enabled, "ports": ports})
        save_json_atomic(CONFIG_FILE, cfg)

        write_log(f"添加节点成功: 名称=[{name}], IP/域名=[{ip}]")
        return jsonify({"ok": True})
    except Exception as e:
        write_log(f"添加节点异常: {str(e)}")
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/delete", methods=["POST"])
def delete_node():
    try:
        data = request.get_json(silent=True) or {}
        ip = str(data.get("ip", "")).strip()

        if not ip:
            write_log("删除节点失败: IP不能为空")
            return jsonify({"ok": False, "msg": "IP不能为空"})

        cfg = load_config()
        before_len = len(cfg.get("nodes", []))
        cfg["nodes"] = [n for n in cfg.get("nodes", []) if n.get("ip") != ip]
        deleted_count = before_len - len(cfg["nodes"])

        if deleted_count > 0:
            save_json_atomic(CONFIG_FILE, cfg)
            write_log(f"删除节点成功: IP/域名=[{ip}]")
        else:
            write_log(f"删除节点失败: 未找到节点 [{ip}]")

        if os.path.exists(STATUS_FILE):
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    status = json.load(f)

                if ip in status:
                    del status[ip]
                    save_json_atomic(STATUS_FILE, status)
            except Exception as e:
                print(f"[Warning] 删除状态节点失败: {e}")

        return jsonify({"ok": True, "deleted": deleted_count})
    except Exception as e:
        write_log(f"删除节点异常: {str(e)}")
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/edit", methods=["POST"])
def edit_node():
    try:
        data = request.get_json(silent=True) or {}
        old_ip = str(data.get("old_ip", "")).strip()
        new_ip = str(data.get("ip", "")).strip()
        new_name = str(data.get("name", "")).strip() or new_ip

        if not old_ip or not new_ip:
            write_log("编辑节点失败: IP或域名不能为空")
            return jsonify({"ok": False, "msg": "IP或域名不能为空"})

        cfg = load_config()
        nodes = cfg.get("nodes", [])
        target = next((n for n in nodes if n.get("ip") == old_ip), None)

        if target is None:
            write_log(f"编辑节点失败: 未找到节点 [{old_ip}]")
            return jsonify({"ok": False, "msg": "未找到节点"})

        if new_ip != old_ip and any(n.get("ip") == new_ip for n in nodes):
            write_log(f"编辑节点失败: 节点 [{new_ip}] 已存在")
            return jsonify({"ok": False, "msg": "新 IP/域名已存在"})

        icmp_enabled = bool(data.get("icmp_enabled", target.get("icmp_enabled", True)))
        ports_raw = data.get("ports", target.get("ports", []))
        if isinstance(ports_raw, str):
            candidates = re.split(r"[,，\s]+", ports_raw.strip())
        elif isinstance(ports_raw, list):
            candidates = ports_raw
        else:
            candidates = []
        ports = []
        for value in candidates:
            if str(value).strip():
                try:
                    port = int(value)
                    if not 1 <= port <= 65535:
                        raise ValueError
                    if port not in ports:
                        ports.append(port)
                except (TypeError, ValueError):
                    return jsonify({"ok": False, "msg": f"无效端口：{value}，端口范围为 1-65535"})
        if not icmp_enabled and not ports:
            return jsonify({"ok": False, "msg": "请至少启用 ICMP Ping 或填写一个 TCP 端口"})
        target["name"] = new_name
        target["ip"] = new_ip
        target["icmp_enabled"] = icmp_enabled
        target["ports"] = ports
        save_json_atomic(CONFIG_FILE, cfg)

        # IP 改变后清理旧状态，避免旧 IP 残留在面板。
        if old_ip != new_ip and os.path.exists(STATUS_FILE):
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    status = json.load(f)
                if old_ip in status:
                    del status[old_ip]
                    save_json_atomic(STATUS_FILE, status)
            except Exception as e:
                print(f"[Warning] 编辑节点清理旧状态失败: {e}")

        # 仅修改名称时，同步现有状态中的名称。
        if old_ip == new_ip and os.path.exists(STATUS_FILE):
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    status = json.load(f)
                if new_ip in status:
                    status[new_ip]["name"] = new_name
                    status[new_ip]["ip"] = new_ip
                    save_json_atomic(STATUS_FILE, status)
            except Exception as e:
                print(f"[Warning] 编辑节点同步状态失败: {e}")

        write_log(f"编辑节点成功: [{old_ip}] -> 名称=[{new_name}], IP/域名=[{new_ip}]")
        return jsonify({"ok": True})
    except Exception as e:
        write_log(f"编辑节点异常: {str(e)}")
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/reorder", methods=["POST"])
def reorder_nodes():
    try:
        data = request.get_json(silent=True) or {}
        order = data.get("nodes", [])

        if not isinstance(order, list):
            return jsonify({"ok": False, "msg": "排序数据格式错误"})

        cfg = load_config()
        current_nodes = cfg.get("nodes", [])

        current_ips = [str(n.get("ip", "")).strip() for n in current_nodes]
        requested_ips = []
        for item in order:
            if isinstance(item, dict):
                ip = str(item.get("ip", "")).strip()
            else:
                ip = str(item).strip()
            if ip:
                requested_ips.append(ip)

        # 必须与现有节点完全一致，防止排序请求意外增删节点。
        if len(requested_ips) != len(current_ips) or set(requested_ips) != set(current_ips):
            return jsonify({"ok": False, "msg": "排序数据与当前节点不一致"})

        node_map = {str(n.get("ip", "")).strip(): n for n in current_nodes}
        cfg["nodes"] = [node_map[ip] for ip in requested_ips]
        save_json_atomic(CONFIG_FILE, cfg)

        write_log("监控节点排序已更新")
        return jsonify({"ok": True})
    except Exception as e:
        write_log(f"监控节点排序异常: {str(e)}")
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/worker", methods=["POST"])
def worker():
    try:
        data = request.get_json(silent=True) or {}
        worker_url = str(data.get("worker", "")).strip()

        cfg = load_config()
        cfg["worker"] = worker_url
        save_json_atomic(CONFIG_FILE, cfg)

        write_log(f"更新 Telegram Worker 配置: URL=[{worker_url if worker_url else '空'}]")
        return jsonify({"ok": True})
    except Exception as e:
        write_log(f"更新 Telegram Worker 配置失败: {str(e)}")
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/interval", methods=["POST"])
def interval():
    try:
        data = request.get_json(silent=True) or {}
        raw_val = data.get("interval", 60)

        try:
            value = int(raw_val)
        except (ValueError, TypeError):
            value = 60

        if value < 5:
            value = 5

        cfg = load_config()
        cfg["interval"] = value
        save_json_atomic(CONFIG_FILE, cfg)

        write_log(f"更新检测频率成功: [{value}] 秒")
        return jsonify({"ok": True, "interval": value})
    except Exception as e:
        write_log(f"更新检测频率失败: {str(e)}")
        return jsonify({"ok": False, "error": str(e)})




@app.route("/api/location/<path:target>")
def ip_location(target):
    """服务器端查询 ip-api.com，并永久缓存成功结果。"""
    original_target, resolved_ip = normalize_lookup_target(target)
    if not original_target or not resolved_ip:
        return jsonify({"ok": False, "location": "未知", "error": "无法解析 IP 或域名"}), 400

    cache_key = original_target
    with IP_CACHE_LOCK:
        cache = load_ip_cache()
        cached = cache.get(cache_key)
        if isinstance(cached, dict) and cached.get("location") and cached.get("version") == IP_CACHE_VERSION:
            return jsonify({
                "ok": True,
                "location": cached["location"],
                "ip": cached.get("ip", resolved_ip),
                "cached": True
            })

    try:
        data = query_ip_api(resolved_ip)
        if not data:
            raise RuntimeError("ip-api.com 返回空数据")

        location = format_ip_location(data)
        if location == "未知":
            return jsonify({"ok": False, "location": "未知", "ip": resolved_ip}), 502

        entry = {
            "location": location,
            "ip": resolved_ip,
            "updated_at": int(time.time()),
            "version": IP_CACHE_VERSION
        }
        with IP_CACHE_LOCK:
            cache = load_ip_cache()
            cache[cache_key] = entry
            save_ip_cache(cache)

        return jsonify({"ok": True, "location": location, "ip": resolved_ip, "cached": False})
    except Exception as e:
        print(f"[IP Location Error] 查询 {original_target} ({resolved_ip}) 失败: {e}")
        return jsonify({"ok": False, "location": "查询失败", "ip": resolved_ip}), 502


@app.route("/api/status")
def status():
    if not os.path.exists(STATUS_FILE):
        return jsonify([])

    try:
        with open(STATUS_FILE, "r", encoding="utf-8") as f:
            status_data = json.load(f)

        cfg = load_config()

        result = [
            status_data[ip]
            for n in cfg.get("nodes", [])
            if (ip := n.get("ip")) in status_data
        ]
        return jsonify(result)
    except Exception as e:
        print(f"[Error] 读取状态失败: {e}")
        return jsonify([])


@app.route("/api/logs")
def logs():
    if not os.path.exists(LOG_FILE):
        return jsonify([])

    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            last_lines = list(deque(f, maxlen=100))
        return jsonify(last_lines)
    except Exception as e:
        print(f"[Error] 读取日志失败: {e}")
        return jsonify([])


@app.route("/api/logs/clear", methods=["POST", "GET"])
def clear_logs_file():
    """彻底清空日志接口（返回结果与日志写入完全解耦）"""
    log_dir = os.path.dirname(LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)

    cleared = False

    # 1. 优先尝试 Python 原生清空
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.truncate(0)
        cleared = True
    except PermissionError:
        # 2. 降级使用 sudo truncate 强行清空并修复权限
        res = subprocess.run(["sudo", "/usr/bin/truncate", "-s", "0", LOG_FILE], capture_output=True)
        if res.returncode != 0:
            res = subprocess.run(["sudo", "truncate", "-s", "0", LOG_FILE], capture_output=True)

        subprocess.run(["sudo", "chmod", "666", LOG_FILE], check=False)
        if res.returncode == 0:
            cleared = True

    # 3. 优先响应前端，确保页面显示成功
    if cleared:
        write_log("系统终端日志已被清空并重新初始化")
        return jsonify({"ok": True})
    else:
        return jsonify({"ok": False, "error": "无法清空日志文件，请检查系统权限"})


@app.route("/api/service/<action>")
def service(action):
    allowed_actions = {"start", "stop", "restart"}
    if action not in allowed_actions:
        write_log(f"非法服务操作指令: [{action}]")
        return jsonify({"ok": False, "msg": "非法的服务指令"})

    action_map = {"start": "启动", "stop": "停止", "restart": "重启"}
    action_name = action_map.get(action, action)

    try:
        result = subprocess.run(
            ["sudo", "systemctl", action, "tcpingmonitor"],
            timeout=10,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            action_str = f"{time.strftime('%H:%M:%S')} ({action_name})"
            set_last_action(action_str)
            write_log(f"发送服务指令成功: [{action_name}]")
            return jsonify({"ok": True})
        else:
            err_msg = result.stderr.strip()
            write_log(f"发送服务指令失败: [{action_name}], 错误原因: {err_msg}")
            return jsonify({"ok": False, "error": err_msg})

    except subprocess.TimeoutExpired:
        write_log(f"发送服务指令超时: [{action_name}]")
        return jsonify({"ok": False, "error": "指令执行超时"})
    except Exception as e:
        write_log(f"发送服务指令异常: [{action_name}], 详情: {str(e)}")
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/system")
def system_info():
    running = False
    uptime_sec = 0

    try:
        res = subprocess.run(
            ["systemctl", "is-active", "tcpingmonitor"],
            capture_output=True,
            text=True,
            timeout=3
        )
        running = (res.stdout.strip() == "active")

        if running:
            res_mono = subprocess.run(
                ["systemctl", "show", "tcpingmonitor", "--property=ActiveEnterTimestampMonotonic"],
                capture_output=True,
                text=True,
                timeout=3
            )
            val_str = res_mono.stdout.strip().replace("ActiveEnterTimestampMonotonic=", "")
            if val_str.isdigit() and int(val_str) > 0:
                mono_us = int(val_str)
                if os.path.exists("/proc/uptime"):
                    with open("/proc/uptime", "r") as f:
                        sys_uptime = float(f.readline().split()[0])
                    uptime_sec = max(0, int(sys_uptime - (mono_us / 1000000)))
                else:
                    uptime_sec = int(time.time() - APP_START_TIME)
            else:
                uptime_sec = int(time.time() - APP_START_TIME)
    except Exception as e:
        print(f"[Error] 获取真实运行状态失败: {e}")
        running = True
        uptime_sec = int(time.time() - APP_START_TIME)

    return jsonify({
        "running": running,
        "uptime": uptime_sec,
        "last_action": get_last_action()
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
