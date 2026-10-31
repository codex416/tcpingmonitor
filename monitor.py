#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import subprocess
import threading
import requests
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

BASE_DIR = "/opt/tcpingmonitor"
CONFIG = os.path.join(BASE_DIR, "config.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")
STATUS_FILE = os.path.join(BASE_DIR, "status.json")


class Monitor:
    def __init__(self):
        self.running_nodes = {}
        self.status_lock = threading.Lock()
        os.makedirs(LOG_DIR, exist_ok=True)

    def log(self, msg):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        text = f"[{timestamp}] {msg}"
        print(text, flush=True)
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(text + "\n")
            try:
                os.chmod(LOG_FILE, 0o666)
            except Exception:
                pass
        except Exception as e:
            print(f"[Log Error] 写入日志失败: {e}")

    def load_config(self):
        try:
            with open(CONFIG, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            if not isinstance(cfg, dict):
                raise ValueError("配置格式错误")
            cfg.setdefault("nodes", [])
            cfg.setdefault("worker", "")
            cfg.setdefault("interval", 60)
            return cfg
        except Exception:
            return {"nodes": [], "worker": "", "interval": 60}

    def _read_status(self):
        try:
            with open(STATUS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def save_status(self, data):
        temp_file = f"{STATUS_FILE}.tmp"
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            os.replace(temp_file, STATUS_FILE)
            try:
                os.chmod(STATUS_FILE, 0o666)
            except Exception:
                pass
        except Exception as e:
            print(f"[Status Save Error] 保存状态失败: {e}")

    def update_icmp_status(self, node, status, delay="-", fail=0):
        with self.status_lock:
            data = self._read_status()
            item = data.setdefault(node["ip"], {})
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            old_icmp = item.get("icmp", {})
            offline_since = old_icmp.get("offline_since")
            if status == "离线":
                if old_icmp.get("status") != "离线" or not offline_since:
                    offline_since = now
            else:
                offline_since = None
            item.update({"name": node["name"], "ip": node["ip"], "status": status,
                         "delay": delay, "fail": fail, "last": now})
            item["icmp"] = {"enabled": True, "status": status, "delay": delay,
                            "fail": fail, "last": now, "offline_since": offline_since}
            item.setdefault("tcp", {})
            self.save_status(data)

    def update_tcp_status(self, node, port, status, delay="-", fail=0, stopped=False):
        with self.status_lock:
            data = self._read_status()
            item = data.setdefault(node["ip"], {})
            item.update({"name": node["name"], "ip": node["ip"]})
            tcp = item.setdefault("tcp", {})
            old = tcp.get(str(port), {})
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            offline_since = old.get("offline_since")
            if status == "离线":
                if old.get("status") != "离线" or not offline_since:
                    offline_since = now
            else:
                offline_since = None
            tcp[str(port)] = {
                "status": status, "delay": delay, "fail": fail,
                "stopped": stopped, "last": now,
                "offline_since": offline_since
            }
            self.save_status(data)

    def update_icmp_disabled(self, node):
        with self.status_lock:
            data = self._read_status()
            item = data.setdefault(node["ip"], {})
            item.update({"name": node["name"], "ip": node["ip"],
                         "status": "未启用", "delay": "-", "fail": 0,
                         "last": "-"})
            item["icmp"] = {"enabled": False, "status": "未启用", "delay": "-",
                            "fail": 0, "last": "-", "offline_since": None}
            item.setdefault("tcp", {})
            self.save_status(data)

    def delete_status(self, ip):
        with self.status_lock:
            data = self._read_status()
            if ip in data:
                del data[ip]
                self.save_status(data)

    def ping(self, ip):
        try:
            result = subprocess.run(["ping", "-c", "1", "-W", "3", ip],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5)
            if result.returncode != 0:
                return False, "-"
            m = re.search(r'time[=<]?\s*([\d.]+)', result.stdout)
            return (True, m.group(1) + "ms") if m else (True, "-")
        except Exception:
            return False, "-"

    def tcping(self, host, port):
        started = time.perf_counter()
        try:
            with socket.create_connection((str(host).strip("[]"), int(port)), timeout=2.5):
                elapsed = (time.perf_counter() - started) * 1000
                return True, f"{elapsed:.1f}ms"
        except (OSError, ValueError, OverflowError):
            return False, "-"

    def notify(self, node, worker, protocol="ICMP", port=None):
        if not worker:
            return
        target = f"{node['ip']}:{int(port)}" if port is not None else str(node["ip"])
        payload = {"name": node["name"], "ip": node["ip"], "status": "DOWN",
                   "protocol": protocol, "target": target,
                   "message": f"{protocol} 故障：{target}",
                   "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        if port is not None:
            payload["port"] = int(port)
        try:
            # 每个协议/端口单独 POST，绝不把 ICMP 与 TCP 故障合并成一条通知。
            response = requests.post(worker, json=payload, timeout=10)
            response.raise_for_status()
            self.log(f"{node['name']} {protocol} {target} TG独立通知成功")
        except Exception as e:
            self.log(f"{node['name']} {protocol} {target} TG通知失败: {str(e)}")

    @staticmethod
    def normalized_ports(node):
        raw = node.get("ports", [])
        if isinstance(raw, str):
            raw = re.split(r"[,，\s]+", raw.strip())
        result = []
        for value in raw if isinstance(raw, list) else []:
            try:
                port = int(value)
                if 1 <= port <= 65535 and port not in result:
                    result.append(port)
            except (TypeError, ValueError):
                continue
        return result

    def _run_target_cycle(self, node, worker, protocol, port=None):
        """ICMP/TCP 共用同一套五次确认：首测失败后按 3/5/2/1 秒重试。"""
        target = f"{node['ip']}:{port}" if port is not None else node["ip"]
        check = (lambda: self.tcping(node["ip"], port)) if protocol == "TCP" else (lambda: self.ping(node["ip"]))

        def save(status, delay="-", fail=0, stopped=False):
            if protocol == "TCP":
                self.update_tcp_status(node, port, status, delay, fail, stopped)
            else:
                self.update_icmp_status(node, status, delay, fail)

        ok, delay = check()  # 第一次检测
        if ok:
            save("在线", delay, 0, False)
            self.log(f"{node['name']} {protocol} {target} 在线 {delay}")
            return True

        save("检测中", "-", 1, False)
        self.log(f"{node['name']} {protocol} {target} 第一次失败，3 秒后重试")
        waits = (3, 5, 2, 1)
        for attempt, wait_seconds in enumerate(waits, start=2):
            time.sleep(wait_seconds)
            # 等待期间若节点/端口已被删除或协议被关闭，则不再继续探测。
            cfg = self.load_config()
            current = next((n for n in cfg.get("nodes", []) if n.get("ip") == node["ip"]), None)
            if current is None:
                return False
            if protocol == "ICMP" and not current.get("icmp_enabled", True):
                self.update_icmp_disabled(current)
                return False
            if protocol == "TCP" and port not in self.normalized_ports(current):
                return False
            node = current
            ok, delay = check()
            if ok:
                save("在线", delay, 0, False)
                self.log(f"{node['name']} {protocol} {target} 第{attempt}次检测成功，恢复在线 {delay}")
                return True
            save("检测中", "-", attempt, False)
            self.log(f"{node['name']} {protocol} {target} 第{attempt}次失败")

        # 第四、第五次都失败，正式离线。第五次是最后一次重试结果。
        save("离线", "-", 5, True)
        self.log(f"{node['name']} {protocol} {target} 第四、第五次均失败，正式判定离线并停止检测")
        self.notify(node, worker, protocol, port)
        return False

    def check_node(self, original_node):
        ip = original_node["ip"]
        name = original_node.get("name", ip)
        stopped = set()
        try:
            while True:
                cfg = self.load_config()
                node = next((n for n in cfg.get("nodes", []) if n.get("ip") == ip), None)
                if not node:
                    self.delete_status(ip)
                    self.log(f"{name} 已删除或 IP 已修改")
                    break
                name = node.get("name") or ip
                worker = cfg.get("worker", "")
                interval = max(5, int(cfg.get("interval", 60) or 60))
                ports = self.normalized_ports(node)

                # 已确认离线的目标在本监控进程生命周期内停止；ICMP 与每个 TCP 端口互不影响。
                targets = []
                if node.get("icmp_enabled", True) and "ICMP" not in stopped:
                    targets.append(("ICMP", None))
                elif not node.get("icmp_enabled", True):
                    self.update_icmp_disabled(node)
                    stopped.discard("ICMP")
                for port in ports:
                    key = ("TCP", port)
                    if key not in stopped:
                        targets.append(key)

                if targets:
                    with ThreadPoolExecutor(max_workers=min(17, len(targets))) as pool:
                        futures = {
                            pool.submit(self._run_target_cycle, node, worker, protocol, port): (protocol, port)
                            for protocol, port in targets
                        }
                        for future, key in [(f, futures[f]) for f in futures]:
                            try:
                                still_online = future.result()
                                # True means this round completed online; False can mean offline or removed/disabled.
                                if not still_online:
                                    protocol, port = key
                                    latest = self.load_config()
                                    current = next((n for n in latest.get("nodes", []) if n.get("ip") == ip), None)
                                    if current:
                                        if protocol == "ICMP" and current.get("icmp_enabled", True):
                                            st = self._read_status().get(ip, {}).get("icmp", {})
                                            if st.get("status") == "离线": stopped.add("ICMP")
                                        elif protocol == "TCP" and port in self.normalized_ports(current):
                                            st = self._read_status().get(ip, {}).get("tcp", {}).get(str(port), {})
                                            if st.get("status") == "离线": stopped.add(("TCP", port))
                            except Exception as e:
                                self.log(f"{name} {key} 检测异常: {e}")

                # 清理已删除端口的状态，同时保留离线时间等有效状态字段。
                with self.status_lock:
                    all_status = self._read_status()
                    current = all_status.get(ip, {})
                    tcp_state = current.get("tcp", {})
                    allowed = {str(p) for p in ports}
                    current["tcp"] = {p: v for p, v in tcp_state.items() if p in allowed}
                    all_status[ip] = current
                    self.save_status(all_status)

                time.sleep(interval)
        except Exception as e:
            self.log(f"{name} 监控线程异常: {e}")
        finally:
            self.running_nodes.pop(ip, None)

    def manager(self):
        while True:
            cfg = self.load_config()
            configured = {n.get("ip") for n in cfg.get("nodes", []) if n.get("ip")}
            for ip in list(self.running_nodes):
                if ip not in configured:
                    self.running_nodes.pop(ip, None)
            for node in cfg.get("nodes", []):
                ip = node.get("ip")
                if ip and ip not in self.running_nodes:
                    self.running_nodes[ip] = "running"
                    threading.Thread(target=self.check_node, args=(node,), daemon=True).start()
                    self.log(f"启动监控: {node.get('name', ip)}")
            time.sleep(5)

    def start(self):
        self.log("tcpingmonitor启动（ICMP Ping + TCPing）")
        self.manager()


if __name__ == "__main__":
    Monitor().start()
