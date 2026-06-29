
import subprocess
import re
import os
from concurrent.futures import ThreadPoolExecutor

RAW_DIR = "raw"
os.makedirs(RAW_DIR, exist_ok=True)


def run_command(cmd):

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        return result.stdout

    except Exception as e:
        return str(e)


def masscan_scan(target, ports=None):

    if ports:
        cmd = [
            "masscan",
            target,
            "-p", ports,
            "--rate", "1000"
        ]
    else:
        cmd = [
            "masscan",
            target,
            "-p1-65535",
            "--rate", "1000"
        ]

    output = run_command(cmd)

    with open(f"{RAW_DIR}/masscan.txt", "w") as f:
        f.write(output)

    discovered = []

    for line in output.splitlines():

        if "Discovered open port" in line:

            match = re.search(
                r'port (\d+)/',
                line
            )

            if match:
                discovered.append(match.group(1))

    return sorted(list(set(discovered)),
                  key=int)


def nmap_scan(target, ports=None):

    if ports:

        cmd = [
            "nmap",
            "-sV",
            "-sC",
            "-T4",
            "-Pn",
            "-p",
            ",".join(ports),
            target
        ]

    else:

        cmd = [
            "nmap",
            "-sS",
            "-sV",
            "-sC",
            "-T4",
            "-Pn",
            target
        ]

    output = run_command(cmd)

    with open(f"{RAW_DIR}/nmap.txt", "w") as f:
        f.write(output)

    services = []

    for line in output.splitlines():

        if "/tcp" in line and "open" in line:
            services.append(line.strip())

    return services, output


def nbt_scan(target):

    output = run_command(
        ["nbtscan", target]
    )

    with open(f"{RAW_DIR}/nbtscan.txt", "w") as f:
        f.write(output)

    return output


def extract_web_ports(nmap_output):

    web_ports = []

    COMMON_WEB_PORTS = [
        "80", "81", "443", "8000",
        "8080", "8081", "8443",
        "3000", "5000", "8888"
    ]

    for line in nmap_output.splitlines():

        # Ignore lines that don't describe TCP ports
        if "/tcp" not in line:
            continue

        port = line.split("/")[0].strip()

        # Nmap identified HTTP/HTTPS service
        if "http" in line.lower():

            if port.isdigit():
                web_ports.append(port)

        # Common web ports even if Nmap couldn't identify them
        elif port in COMMON_WEB_PORTS:

            web_ports.append(port)

    return sorted(list(set(web_ports)), key=int)


def whatweb_scan(url):

    return (
        "\n========== WHATWEB ==========\n"
        + run_command([
            "whatweb",
            "--no-errors",
            "--color=never",
            url
        ])
    )
def nuclei_scan(url):

    output = run_command([
        "nuclei",
        "-u", url,
        "-severity",
        "critical,high",
        "-silent"
    ])

    if output.strip():

        return (
            "\n========== NUCLEI ==========\n"
            + output
        )

    return "\n========== NUCLEI ==========\nNo findings.\n"
def nikto_scan(url):

    return (
        "\n========== NIKTO ==========\n"
        + run_command([
            "nikto",
            "-host", url
        ])
    )


def scan_single_url(url, use_nikto):

    results = []

    results.append(whatweb_scan(url))
    results.append(nuclei_scan(url))

    if use_nikto:
        results.append(nikto_scan(url))

    return results


def run_web_scans(target,
                   web_ports,
                   use_nikto=False):

    findings = []

    urls = []

    for port in web_ports:

        proto = (
            "https"
            if port in ["443", "8443"]
            else "http"
        )

        urls.append(
            f"{proto}://{target}:{port}"
        )

    with ThreadPoolExecutor(
            max_workers=5) as executor:

        futures = [
            executor.submit(
                scan_single_url,
                url,
                use_nikto
            )
            for url in urls
        ]

        for future in futures:
            findings.extend(future.result())

    return findings

