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
import fcntl
from contextlib import contextmanager
from datetime import datetime

BASE_DIR = "/opt/tcpingmonitor"
CONFIG = os.path.join(BASE_DIR, "config.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "monitor.log")
STATUS_FILE = os.path.join(BASE_DIR, "status.json")
TARGET_EPOCH_FILE = os.path.join(BASE_DIR, "target_epochs.json")
CONTROL_LOCK_FILE = os.path.join(BASE_DIR, "config_control.lock")
MONITOR_CONTROL_HOST = "127.0.0.1"
MONITOR_CONTROL_PORT = 49381


class Monitor:
    def __init__(self):
        # IP -> Thread。保存真实线程对象，避免仅用字符串标记导致旧线程
        # 尚未退出时被 manager 误判为不存在并启动第二个检测线程。
        self.running_nodes = {}
        self.running_nodes_lock = threading.Lock()
        # 每个 ICMP/TCP 目标独立线程；新增目标无需等待节点其他目标的检测周期。
        self.running_targets = {}
        self.running_targets_lock = threading.Lock()
        self.status_lock = threading.Lock()
        # 仅在当前 Python 进程内有效：服务重启会重新创建 Monitor，
        # 因此所有目标会重新检测；单个监控线程异常重建不会丢失停止状态。
        self.stopped_targets = set()
        self.stopped_targets_lock = threading.Lock()
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

    def ensure_icmp_disabled(self, node):
        """仅在状态尚未标记为未启用时写入，避免协调线程每秒重复写文件。"""
        with self.status_lock:
            data = self._read_status()
            item = data.get(node["ip"], {})
            icmp = item.get("icmp", {}) if isinstance(item, dict) else {}
            already_disabled = (
                isinstance(item, dict)
                and item.get("status") == "未启用"
                and isinstance(icmp, dict)
                and icmp.get("enabled") is False
                and icmp.get("status") == "未启用"
            )
        if not already_disabled:
            self.update_icmp_disabled(node)

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

    @contextmanager
    def control_lock(self):
        os.makedirs(BASE_DIR, exist_ok=True)
        with open(CONTROL_LOCK_FILE, "a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def target_epoch(self, ip, protocol, port=None):
        key = f"{ip}|{str(protocol).upper()}|{int(port) if port is not None else 0}"
        try:
            with open(TARGET_EPOCH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return int(data.get(key, 0)) if isinstance(data, dict) else 0
        except Exception:
            return 0

    @staticmethod
    def target_key(ip, protocol, port=None, epoch=0):
        return (str(ip), str(protocol).upper(), int(port) if port is not None else None, int(epoch))

    def target_is_current(self, ip, protocol, port, epoch):
        """与编辑接口串行校验目标版本及当前配置，阻止旧周期继续探测。"""
        with self.control_lock():
            if self.target_epoch(ip, protocol, port) != epoch:
                return False
            cfg = self.load_config()
            node = next((n for n in cfg.get("nodes", []) if n.get("ip") == ip), None)
            if node is None:
                return False
            if protocol == "ICMP":
                return bool(node.get("icmp_enabled", True))
            return port in self.normalized_ports(node)

    def is_target_stopped(self, ip, protocol, port=None):
        key = self.target_key(ip, protocol, port, self.target_epoch(ip, protocol, port))
        with self.stopped_targets_lock:
            return key in self.stopped_targets

    def mark_target_stopped(self, ip, protocol, port=None, epoch=0):
        """原子地标记指定配置版本的目标停止。"""
        key = self.target_key(ip, protocol, port, epoch)
        with self.stopped_targets_lock:
            if key in self.stopped_targets:
                return False
            self.stopped_targets.add(key)
            return True

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
        """ICMP/TCP 共用五次确认；配置版本变化时立即废弃旧检测周期。"""
        cycle_epoch = self.target_epoch(node["ip"], protocol, port)
        target = f"{node['ip']}:{port}" if port is not None else node["ip"]
        check = (lambda: self.tcping(node["ip"], port)) if protocol == "TCP" else (lambda: self.ping(node["ip"]))

        def save(status, delay="-", fail=0, stopped=False):
            if self.target_epoch(node["ip"], protocol, port) != cycle_epoch:
                return False
            if protocol == "TCP":
                self.update_tcp_status(node, port, status, delay, fail, stopped)
            else:
                self.update_icmp_status(node, status, delay, fail)
            return True

        if not self.target_is_current(node["ip"], protocol, port, cycle_epoch):
            return False
        ok, delay = check()  # 第一次检测
        if self.target_epoch(node["ip"], protocol, port) != cycle_epoch:
            return False
        if ok:
            if not save("在线", delay, 0, False):
                return False
            self.log(f"{node['name']} {protocol} {target} 在线 {delay}")
            return True

        if not save("检测中", "-", 1, False):
            return False
        self.log(f"{node['name']} {protocol} {target} 第一次失败，3 秒后重试")
        waits = (3, 5, 2, 1)
        for attempt, wait_seconds in enumerate(waits, start=2):
            time.sleep(wait_seconds)
            # 等待期间若节点/端口已被删除或协议被关闭，则不再继续探测。
            if not self.target_is_current(node["ip"], protocol, port, cycle_epoch):
                return False
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
            if not self.target_is_current(node["ip"], protocol, port, cycle_epoch):
                return False
            ok, delay = check()
            if self.target_epoch(node["ip"], protocol, port) != cycle_epoch:
                return False
            if ok:
                if not save("在线", delay, 0, False):
                    return False
                self.log(f"{node['name']} {protocol} {target} 第{attempt}次检测成功，恢复在线 {delay}")
                return True
            if not save("检测中", "-", attempt, False):
                return False
            self.log(f"{node['name']} {protocol} {target} 第{attempt}次失败")

        # 最终判定前再次确认目标仍在配置中，避免节点/端口刚被删除时
        # 旧检测线程仍然写入离线状态并发送过期 TG 通知。
        # 与 Web 编辑接口共用跨进程文件锁：最终校验、停止登记和通知串行化，
        # 防止编辑已提交后旧检测周期仍写离线状态或发送过期通知。
        with self.control_lock():
            if self.target_epoch(node["ip"], protocol, port) != cycle_epoch:
                return False
            latest_cfg = self.load_config()
            current = next((n for n in latest_cfg.get("nodes", [])
                            if n.get("ip") == node["ip"]), None)
            if current is None:
                return False
            if protocol == "ICMP" and not current.get("icmp_enabled", True):
                return False
            if protocol == "TCP" and port not in self.normalized_ports(current):
                return False
            node = current
            worker = latest_cfg.get("worker", worker)
            if not self.mark_target_stopped(node["ip"], protocol, port, cycle_epoch):
                self.log(f"{node['name']} {protocol} {target} 已停止，跳过重复通知")
                return False
            if not save("离线", "-", 5, True):
                return False
            self.log(f"{node['name']} {protocol} {target} 第五次失败，正式判定离线并停止检测")
            self.notify(node, worker, protocol, port)
        return False

    def _target_enabled(self, node, protocol, port):
        if protocol == "ICMP":
            return bool(node.get("icmp_enabled", True))
        return port in self.normalized_ports(node)

    def _run_target_worker(self, ip, protocol, port, epoch):
        """单个目标独立循环；配置新增/修改不会重启同节点的其他目标。"""
        key = (ip, protocol, port, epoch)
        current_thread = threading.current_thread()
        try:
            while True:
                if self.target_epoch(ip, protocol, port) != epoch:
                    return
                cfg = self.load_config()
                node = next((n for n in cfg.get("nodes", []) if n.get("ip") == ip), None)
                if node is None or not self._target_enabled(node, protocol, port):
                    return
                if self.is_target_stopped(ip, protocol, port):
                    return

                worker = cfg.get("worker", "")
                interval = max(5, int(cfg.get("interval", 60) or 60))
                self._run_target_cycle(node, worker, protocol, port)

                # 五次失败后该目标已在本进程停止；其他目标线程不受影响。
                if self.is_target_stopped(ip, protocol, port):
                    return
                # 等待期间若目标版本变化，尽快退出旧线程；新版本由扫描器立即创建。
                for _ in range(interval):
                    if self.target_epoch(ip, protocol, port) != epoch:
                        return
                    time.sleep(1)
        except Exception as e:
            self.log(f"{ip} {protocol} {port if port is not None else ''} 独立检测线程异常: {e}")
        finally:
            with self.running_targets_lock:
                if self.running_targets.get(key) is current_thread:
                    self.running_targets.pop(key, None)

    def _ensure_target_worker(self, node, protocol, port=None):
        """确保当前配置版本的目标线程已经存在；返回是否已启动或正在运行。"""
        ip = node["ip"]
        epoch = self.target_epoch(ip, protocol, port)
        if self.is_target_stopped(ip, protocol, port):
            return False
        key = (ip, protocol, port, epoch)
        with self.running_targets_lock:
            existing = self.running_targets.get(key)
            if existing is not None and existing.is_alive():
                return True
            thread = threading.Thread(
                target=self._run_target_worker,
                args=(ip, protocol, port, epoch),
                name=f"target-{protocol}-{ip}-{port or 0}",
                daemon=True
            )
            self.running_targets[key] = thread
            thread.start()
        label = f"{ip}:{port}" if port is not None else ip
        self.log(f"即时启动目标检测线程: {protocol} {label} epoch={epoch}")
        return True

    def check_node(self, original_node):
        """节点协调线程只负责发现目标；每个目标由独立线程按周期检测。"""
        ip = original_node["ip"]
        name = original_node.get("name", ip)
        try:
            while True:
                cfg = self.load_config()
                node = next((n for n in cfg.get("nodes", []) if n.get("ip") == ip), None)
                if not node:
                    self.delete_status(ip)
                    self.log(f"{name} 已删除或 IP 已修改")
                    break

                name = node.get("name") or ip
                if node.get("icmp_enabled", True):
                    self._ensure_target_worker(node, "ICMP")
                else:
                    self.ensure_icmp_disabled(node)

                ports = self.normalized_ports(node)
                for port in ports:
                    self._ensure_target_worker(node, "TCP", port)

                # 清理配置中已不存在端口的旧状态；其他端口状态不变。
                with self.status_lock:
                    all_status = self._read_status()
                    current = all_status.get(ip)
                    if isinstance(current, dict):
                        tcp_state = current.get("tcp", {})
                        if isinstance(tcp_state, dict):
                            allowed = {str(p) for p in ports}
                            current["tcp"] = {p: v for p, v in tcp_state.items() if p in allowed}
                            self.save_status(all_status)

                # 每秒扫描一次配置，新增节点内目标通常在 1 秒内启动。
                time.sleep(1)
        except Exception as e:
            self.log(f"{name} 节点协调线程异常: {e}")
        finally:
            current_thread = threading.current_thread()
            with self.running_nodes_lock:
                if self.running_nodes.get(ip) is current_thread:
                    self.running_nodes.pop(ip, None)

    def command_server(self):
        """接收 Web 即时启动命令；只有目标线程已启动/已运行才返回成功确认。"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((MONITOR_CONTROL_HOST, MONITOR_CONTROL_PORT))
            server.listen(16)
            self.log(f"即时检测控制通道已启动: {MONITOR_CONTROL_HOST}:{MONITOR_CONTROL_PORT}")
            while True:
                conn, _ = server.accept()
                with conn:
                    response = {"ok": False, "accepted": 0, "started": [], "error": "无效控制命令"}
                    try:
                        conn.settimeout(3)
                        chunks = []
                        total = 0
                        while True:
                            chunk = conn.recv(4096)
                            if not chunk:
                                break
                            chunks.append(chunk)
                            total += len(chunk)
                            if total > 65536:
                                raise ValueError("控制命令过大")
                        command = json.loads(b"".join(chunks).decode("utf-8"))
                        if command.get("action") != "start_targets":
                            raise ValueError("不支持的控制命令")

                        started = []
                        rejected = []
                        for item in command.get("targets", []):
                            if not isinstance(item, dict):
                                rejected.append("invalid")
                                continue
                            ip = str(item.get("ip", "")).strip()
                            protocol = str(item.get("protocol", "")).upper()
                            try:
                                port = int(item["port"]) if protocol == "TCP" else None
                            except (KeyError, TypeError, ValueError):
                                rejected.append(f"{ip} TCP invalid-port")
                                continue
                            if not ip or protocol not in ("ICMP", "TCP"):
                                rejected.append(f"{ip} invalid-protocol")
                                continue
                            cfg = self.load_config()
                            node = next((n for n in cfg.get("nodes", []) if n.get("ip") == ip), None)
                            if node is None or not self._target_enabled(node, protocol, port):
                                rejected.append(f"{ip} {protocol} {port or ''} not-enabled")
                                continue
                            if self._ensure_target_worker(node, protocol, port):
                                started.append({"ip": ip, "protocol": protocol, "port": port})
                            else:
                                rejected.append(f"{ip} {protocol} {port or ''} stopped")

                        expected = len(command.get("targets", []))
                        response = {
                            "ok": len(started) == expected,
                            "accepted": len(started),
                            "started": started,
                            "rejected": rejected,
                            "error": None if len(started) == expected else "部分目标未能启动"
                        }
                    except Exception as e:
                        response = {"ok": False, "accepted": 0, "started": [], "error": str(e)}
                        self.log(f"即时检测控制命令处理失败: {e}")
                    try:
                        conn.sendall(json.dumps(response, ensure_ascii=False).encode("utf-8"))
                    except OSError as e:
                        self.log(f"即时检测启动确认发送失败: {e}")
        except Exception as e:
            self.log(f"即时检测控制通道启动失败: {e}；继续使用配置扫描兜底")
        finally:
            server.close()

    def manager(self):
        while True:
            cfg = self.load_config()
            for node in cfg.get("nodes", []):
                ip = node.get("ip")
                if not ip:
                    continue
                with self.running_nodes_lock:
                    existing = self.running_nodes.get(ip)
                    # 只要旧线程仍存活，就绝不为相同 IP 创建第二个线程。
                    # 节点删除后由旧线程自行发现配置缺失并退出；manager
                    # 不提前删除登记项，避免删除/重新添加时产生并发检测。
                    if existing is not None and existing.is_alive():
                        continue
                    thread = threading.Thread(
                        target=self.check_node,
                        args=(node,),
                        name=f"monitor-{ip}",
                        daemon=True
                    )
                    self.running_nodes[ip] = thread
                    thread.start()
                self.log(f"启动监控: {node.get('name', ip)}")
            time.sleep(1)

    def start(self):
        self.log("tcpingmonitor启动（ICMP Ping + TCPing）")
        command_thread = threading.Thread(target=self.command_server,
                                          name="monitor-command-server", daemon=True)
        command_thread.start()
        self.manager()


if __name__ == "__main__":
    Monitor().start()
