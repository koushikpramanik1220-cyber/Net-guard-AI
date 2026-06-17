#!/usr/bin/env python3
import argparse
import concurrent.futures as cf
import csv
import json
import os
import socket
import ssl
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlsplit

from google import genai

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False

THREADS_DEFAULT = 80
PORT_TIMEOUT = 0.8
BANNER_TIMEOUT = 1.2

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

@dataclass
class PortResult:
    port: int
    service_guess: str = "Unknown"
    banner: str = ""
    tls: bool = False

def normalize_target(target: str) -> str:
    target = target.strip()
    if "://" in target:
        return urlsplit(target).hostname or target
    return target

def parse_ports(spec: str):
    ports = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(chunk))
    return sorted(set(p for p in ports if 1 <= p <= 65535))

def banner_from_socket(sock, port):
    sock.settimeout(BANNER_TIMEOUT)
    try:
        if port in (443, 8443, 465, 993, 995):
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname="localhost") as ssock:
                try:
                    ssock.sendall(b"HEAD / HTTP/1.0
Host: localhost

")
                except Exception:
                    pass
                try:
                    data = ssock.recv(1024)
                    return data.decode(errors="ignore").strip(), True
                except Exception:
                    return "", True
        try:
            sock.sendall(b"HEAD / HTTP/1.0
Host: localhost

")
        except Exception:
            pass
        try:
            data = sock.recv(1024)
            return data.decode(errors="ignore").strip(), False
        except Exception:
            return "", False
    except Exception:
        return "", False

def infer_service(port, banner):
    guess = COMMON_PORTS.get(port, "Unknown")
    if banner:
        low = banner.lower()
        if "ssh" in low:
            return "SSH"
        if "smtp" in low:
            return "SMTP"
        if "ftp" in low:
            return "FTP"
        if "server:" in low or "http" in low:
            return "HTTP/HTTPS"
    return guess

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(PORT_TIMEOUT)
            if s.connect_ex((target, port)) == 0:
                banner, tls = banner_from_socket(s, port)
                return PortResult(
                    port=port,
                    service_guess=infer_service(port, banner),
                    banner=banner[:180],
                    tls=tls
                )
    except Exception:
        return None
    return None

def scan_target(target, ports, threads, console=None):
    results = []
    total = len(ports)
    done = 0

    if console and RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]Scanning[/bold] {task.percentage:>3.0f}%"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {target}", total=total)
            with cf.ThreadPoolExecutor(max_workers=threads) as ex:
                future_map = {ex.submit(scan_port, target, p): p for p in ports}
                for fut in cf.as_completed(future_map):
                    r = fut.result()
                    if r:
                        results.append(r)
                    done += 1
                    progress.update(task, advance=1)
    else:
        with cf.ThreadPoolExecutor(max_workers=threads) as ex:
            future_map = {ex.submit(scan_port, target, p): p for p in ports}
            for fut in cf.as_completed(future_map):
                r = fut.result()
                if r:
                    results.append(r)
                done += 1
                if done % 25 == 0 or done == total:
                    print(f"
[*] Progress: {done}/{total}", end="", flush=True)
        print()

    return sorted(results, key=lambda x: x.port)

def build_report_prompt(target, results):
    payload = [asdict(r) for r in results]
    return f"""
You are writing a defensive security assessment for an authorized test of {target}.
Use only the evidence below; do not invent findings.

Open services:
{json.dumps(payload, indent=2)}

Write:
1. Executive summary.
2. Risk score from 0 to 100 with short justification.
3. Findings table with port, likely service, exposure risk, and defensive concern.
4. Safe remediation guidance focused on hardening, firewalling, patching, and least privilege.
5. Prioritized next steps for an administrator.

Do not include offensive exploitation steps, payloads, or instructions to attack systems.
""".strip()

def generate_ai_report(target, results):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=build_report_prompt(target, results),
    )
    return response.text

def write_outputs(outdir, target, ports, results, report_text):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    md_path = outdir / "Enterprise_Audit_Report.md"
    json_path = outdir / "scan_results.json"
    csv_path = outdir / "scan_results.csv"

    md_path.write_text(report_text, encoding="utf-8")
    json_path.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["port", "service_guess", "banner", "tls"])
        w.writeheader()
        for r in results:
            w.writerow(asdict(r))

    return md_path, json_path, csv_path

def main():
    parser = argparse.ArgumentParser(description="Authorized port scanner with AI-generated defensive report")
    parser.add_argument("target", nargs="?", default="127.0.0.1")
    parser.add_argument("--ports", default="1-1024")
    parser.add_argument("--threads", type=int, default=THREADS_DEFAULT)
    parser.add_argument("--out", default="output")
    parser.add_argument("--no-ai", action="store_true")
    args = parser.parse_args()

    target = normalize_target(args.target)
    ports = parse_ports(args.ports)

    console = Console() if RICH_AVAILABLE else None

    print("=" * 72)
    print("  NETGUARD PRO | AUTHORIZED SECURITY ASSESSMENT REPORTING")
    print("=" * 72)
    print(f"[*] Target: {target}")
    print(f"[*] Ports: {len(ports)}")
    print(f"[*] Threads: {args.threads}")

    results = scan_target(target, ports, max(1, args.threads), console=console)

    print(f"[+] Open ports found: {len(results)}")
    for r in results:
        tls_tag = " TLS" if r.tls else ""
        print(f"    - {r.port}/{r.service_guess}{tls_tag}")

    if args.no_ai:
        report_text = "# Security Report

AI reporting disabled.
"
    else:
        report_text = generate_ai_report(target, results)

    md_path, json_path, csv_path = write_outputs(args.out, target, ports, results, report_text)

    print("
" + "=" * 20 + " FINAL SECURITY AUDIT " + "=" * 20)
    print(report_text)
    print(f"
[+] Saved: {md_path}")
    print(f"[+] Saved: {json_path}")
    print(f"[+] Saved: {csv_path}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("
[!] Interrupted by user")
        sys.exit(130)