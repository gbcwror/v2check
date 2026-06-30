# scripts/converter.py
"""
Xray Share Link <-> JSON Converter
Supports: vless://, vmess://, ss://, trojan://
"""

import json
import base64
from urllib.parse import urlparse, parse_qs, unquote


def b64decode_safe(data: str) -> bytes:
    data = data.strip()
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data)
    except Exception:
        return base64.urlsafe_b64decode(data)


def build_transport_settings(network: str, params: dict) -> dict:
    settings_key = None
    transport = {}

    if network in ("ws", "websocket"):
        settings_key = "wsSettings"
        if "path" in params:
            transport["path"] = unquote(params["path"][0])
        if "host" in params:
            transport["host"] = params["host"][0]

    elif network == "grpc":
        settings_key = "grpcSettings"
        if "serviceName" in params:
            transport["serviceName"] = params["serviceName"][0]
        if "authority" in params:
            transport["authority"] = params["authority"][0]
        if "mode" in params and params["mode"][0] == "multi":
            transport["multiMode"] = True

    elif network == "httpupgrade":
        settings_key = "httpupgradeSettings"
        if "path" in params:
            transport["path"] = unquote(params["path"][0])
        if "host" in params:
            transport["host"] = params["host"][0]

    elif network in ("xhttp", "splithttp"):
        settings_key = "xhttpSettings"
        if "path" in params:
            transport["path"] = unquote(params["path"][0])
        if "host" in params:
            transport["host"] = params["host"][0]
        if "mode" in params:
            transport["mode"] = params["mode"][0]
        if "extra" in params:
            try:
                transport["extra"] = json.loads(unquote(params["extra"][0]))
            except (json.JSONDecodeError, Exception):
                pass

    elif network in ("tcp", "raw"):
        header_type = params.get("headerType", ["none"])[0]
        if header_type == "http":
            settings_key = "tcpSettings"
            transport["header"] = {"type": "http"}
            if "host" in params:
                hosts = params["host"][0].split(",")
                transport["header"]["request"] = {"headers": {"Host": hosts}}

    elif network in ("kcp", "mkcp"):
        settings_key = "kcpSettings"

    if settings_key and transport:
        return {settings_key: transport}
    return {}


def build_security_settings(security: str, params: dict) -> dict:
    result = {}

    if security == "tls":
        tls = {}
        if "sni" in params:
            tls["serverName"] = params["sni"][0]
        if "fp" in params:
            tls["fingerprint"] = params["fp"][0]
        if "alpn" in params:
            tls["alpn"] = params["alpn"][0].split(",")
        if "pcs" in params:
            tls["pinnedPeerCertSha256"] = params["pcs"][0]
        if "vcn" in params:
            tls["verifyPeerCertByName"] = params["vcn"][0]
        if tls:
            result["tlsSettings"] = tls

    elif security == "reality":
        reality = {}
        if "sni" in params:
            reality["serverName"] = params["sni"][0]
        if "fp" in params:
            reality["fingerprint"] = params["fp"][0]
        if "pbk" in params:
            reality["publicKey"] = params["pbk"][0]
        if "sid" in params:
            reality["shortId"] = params["sid"][0]
        if "spx" in params:
            reality["spiderX"] = unquote(params["spx"][0])
        if reality:
            result["realitySettings"] = reality

    return result


def build_stream_settings(params: dict) -> dict:
    network = params.get("type", ["tcp"])[0]
    security = params.get("security", ["none"])[0]

    stream = {"network": network, "security": security}
    stream.update(build_security_settings(security, params))
    stream.update(build_transport_settings(network, params))

    return stream


def parse_vless(link: str):
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    remark = unquote(parsed.fragment) if parsed.fragment else ""

    user = {
        "id": parsed.username,
        "encryption": params.get("encryption", ["none"])[0],
    }
    flow = params.get("flow", [""])[0]
    if flow:
        user["flow"] = flow

    outbound = {
        "protocol": "vless",
        "tag": "proxy",
        "settings": {
            "vnext": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "users": [user]
            }]
        },
        "streamSettings": build_stream_settings(params),
    }

    return outbound, remark


def parse_vmess(link: str):
    raw = link[len("vmess://"):]
    decoded = json.loads(b64decode_safe(raw).decode("utf-8"))

    net = decoded.get("net", "tcp")
    tls_val = decoded.get("tls", "")
    security = tls_val if tls_val else "none"
    remark = decoded.get("ps", "")

    params = {"type": [net], "security": [security]}

    if decoded.get("sni"):
        params["sni"] = [decoded["sni"]]
    if decoded.get("fp"):
        params["fp"] = [decoded["fp"]]
    if decoded.get("alpn"):
        params["alpn"] = [decoded["alpn"]]

    if net in ("ws", "websocket", "httpupgrade"):
        if decoded.get("host"):
            params["host"] = [decoded["host"]]
        if decoded.get("path"):
            params["path"] = [decoded["path"]]
    elif net == "grpc":
        if decoded.get("path"):
            params["serviceName"] = [decoded["path"]]
        if decoded.get("host"):
            params["authority"] = [decoded["host"]]
        if decoded.get("type") == "multi":
            params["mode"] = ["multi"]
    elif net in ("xhttp", "splithttp"):
        if decoded.get("host"):
            params["host"] = [decoded["host"]]
        if decoded.get("path"):
            params["path"] = [decoded["path"]]
        if decoded.get("mode"):
            params["mode"] = [decoded["mode"]]
    elif net in ("tcp", "raw"):
        header_type = decoded.get("type", "none")
        if header_type and header_type != "none":
            params["headerType"] = [header_type]
        if decoded.get("host"):
            params["host"] = [decoded["host"]]

    scy = decoded.get("scy", decoded.get("security", "auto"))
    if not scy:
        scy = "auto"

    outbound = {
        "protocol": "vmess",
        "tag": "proxy",
        "settings": {
            "vnext": [{
                "address": decoded.get("add", ""),
                "port": int(decoded.get("port", 0)),
                "users": [{
                    "id": decoded.get("id", ""),
                    "security": scy,
                }]
            }]
        },
        "streamSettings": build_stream_settings(params),
    }

    return outbound, remark


def parse_ss(link: str):
    raw = link[len("ss://"):]

    fragment = ""
    if "#" in raw:
        raw, fragment = raw.rsplit("#", 1)
        fragment = unquote(fragment)

    if "?" in raw:
        raw = raw.split("?", 1)[0]

    if "@" in raw:
        userinfo_part, server_part = raw.rsplit("@", 1)
        try:
            userinfo = b64decode_safe(userinfo_part).decode("utf-8")
        except Exception:
            userinfo = unquote(userinfo_part)

        if ":" not in userinfo:
            raise ValueError("Invalid SS userinfo")
        method, password = userinfo.split(":", 1)

        if server_part.startswith("["):
            bracket_end = server_part.index("]")
            host = server_part[1:bracket_end]
            port_str = server_part[bracket_end + 2:]
        else:
            host, port_str = server_part.rsplit(":", 1)
        port = int(port_str)

    else:
        decoded_str = b64decode_safe(raw).decode("utf-8")
        if "@" not in decoded_str:
            raise ValueError("Invalid legacy SS link")
        method_pass, server_part = decoded_str.rsplit("@", 1)
        method, password = method_pass.split(":", 1)
        if server_part.startswith("["):
            bracket_end = server_part.index("]")
            host = server_part[1:bracket_end]
            port_str = server_part[bracket_end + 2:]
        else:
            host, port_str = server_part.rsplit(":", 1)
        port = int(port_str)

    outbound = {
        "protocol": "shadowsocks",
        "tag": "proxy",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
            }]
        },
        "streamSettings": {"network": "tcp", "security": "none"},
    }

    return outbound, fragment


def parse_trojan(link: str):
    parsed = urlparse(link)
    params = parse_qs(parsed.query)
    remark = unquote(parsed.fragment) if parsed.fragment else ""

    if "security" not in params:
        params["security"] = ["tls"]

    outbound = {
        "protocol": "trojan",
        "tag": "proxy",
        "settings": {
            "servers": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "password": unquote(parsed.username),
            }]
        },
        "streamSettings": build_stream_settings(params),
    }

    return outbound, remark


def convert_link(link: str):
    """Returns (outbound_dict, remark_string)."""
    link = link.strip()
    if not link:
        raise ValueError("Empty link")

    if link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith("vmess://"):
        return parse_vmess(link)
    elif link.startswith("ss://"):
        return parse_ss(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    else:
        scheme = link.split("://")[0] if "://" in link else "unknown"
        raise ValueError(f"Unsupported protocol: {scheme}")


def get_protocol(link: str) -> str:
    """Extract protocol name from share link."""
    link = link.strip()
    if link.startswith("vless://"):
        return "vless"
    elif link.startswith("vmess://"):
        return "vmess"
    elif link.startswith("ss://"):
        return "ss"
    elif link.startswith("trojan://"):
        return "trojan"
    return "unknown"


def build_xray_config(outbound: dict, socks_port: int) -> dict:
    """Build minimal Xray config for testing."""
    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "tag": "socks-in",
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "settings": {
                "auth": "noauth",
                "udp": True
            }
        }],
        "outbounds": [
            outbound,
            {
                "tag": "direct",
                "protocol": "freedom"
            }
        ]
    }