#!/usr/bin/env python3
from rich.table import Table
from installer import ensure_tool
from scanner import *
from report import save_report
from rich.progress import Progress
from rich.console import Console
import time

console = Console()


def banner():

    console.print("""
====================================================
                RECON FRAMEWORK
====================================================

1. Nmap Only
   -> Service detection & NSE scripts

2. Nmap + Masscan
   -> Fast port discovery + enumeration

3. Nmap + Nbtscan
   -> Service enumeration + NetBIOS

4. Nmap + Nuclei
   -> Service enumeration + vulnerability scan

5. Full Scan
   -> Masscan + Nmap + Nbtscan
      + WhatWeb + Nuclei
      + Optional Nikto

====================================================
""", style="bold cyan")


def print_results(target,
                  services,
                  nbt_output,
                  web_findings,
                  duration,
                  report_file):

    # ---------------- Open Services Table ---------------- #

    table = Table(
        title="Open Services",
        show_lines=True
    )

    table.add_column("Port", style="cyan")
    table.add_column("State", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Version", style="white")

    if services:

        for service in services:

            parts = service.split()

            port = parts[0].split("/")[0]
            state = parts[1]

            service_name = (
                parts[2]
                if len(parts) >= 3
                else "Unknown"
            )

            version = (
                " ".join(parts[3:])
                if len(parts) >= 4
                else "Unknown"
            )

            table.add_row(
                port,
                state,
                service_name,
                version
            )

    else:

        table.add_row(
            "-", "-", "-", "No services found"
        )

    console.print(table)

    # ---------------- NetBIOS ---------------- #

    if nbt_output:

        console.print(
            "\n[bold green]NetBIOS Results[/bold green]"
        )

        console.print(nbt_output)

    # ---------------- Web Findings ---------------- #

    if web_findings:

        console.print(
            "\n[bold green]Web Findings[/bold green]"
        )

        for item in web_findings:

            if item.strip():
                console.print(item)

    # ---------------- Summary ---------------- #

    web_service_count = 0

    for s in services:

        if "http" in s.lower():
            web_service_count += 1

    vuln_count = 0

    for finding in web_findings:

        if finding.strip() and "No findings" not in finding:
            vuln_count += 1

    smb = (
        "Yes"
        if nbt_output.strip()
        else "No"
    )

    console.print("\n" + "=" * 50)

    console.print(
        "[bold cyan]SCAN SUMMARY[/bold cyan]"
    )

    console.print("=" * 50)

    console.print(
        f"Target            : {target}"
    )

    console.print(
        f"Open Ports Found  : {len(services)}"
    )

    console.print(
        f"Web Services      : {web_service_count}"
    )

    console.print(
        f"SMB Services      : {smb}"
    )

    console.print(
        f"Vulnerabilities   : {vuln_count}"
    )

    console.print(
        f"Duration          : {duration}"
    )

    console.print(
        f"\nReport Saved      :"
    )

    console.print(
        f"{report_file}"
    )

    console.print("=" * 50)

def main():

    banner()

    target = input(
        "Enter Target IP/Domain: "
    ).strip()

    ports = input(
        "Enter Ports (blank for auto discovery): "
    ).strip()

    option = input(
        "Choose Option: "
    ).strip()

    use_nikto = False

    if option == "5":

        nikto_choice = input(
            "Run Nikto? (slow) [y/N]: "
        )

        use_nikto = (
            nikto_choice.lower()
            in ["y", "yes"]
        )

    services = []
    nbt_output = ""
    web_findings = []
    start_time = time.time()

    with Progress() as progress:

        task = progress.add_task(
            "[green]Recon Running...",
            total=5
        )

        # Option 1
        if option == "1":

            ensure_tool("nmap")

            supplied_ports = (
                ports.split(",")
                if ports else None
            )

            services, _ = nmap_scan(
                target,
                supplied_ports
            )

            progress.advance(task, 5)

        # Option 2
        elif option == "2":

            ensure_tool("masscan")
            ensure_tool("nmap")

            if ports:
                console.print(
                    "[yellow]Using supplied ports. "
                    "Skipping Masscan.[/yellow]"
                )
                discovered = ports.split(",")

            else:
                discovered = masscan_scan(target)

            progress.advance(task)

            services, _ = nmap_scan(
                target,
                discovered
            )

            progress.advance(task, 4)

        # Option 3
        elif option == "3":

            ensure_tool("nmap")
            ensure_tool("nbtscan")

            supplied_ports = (
                ports.split(",")
                if ports else None
            )

            services, nmap_out = nmap_scan(
                target,
                supplied_ports
            )

            progress.advance(task, 2)

            if (
                "137/tcp" in nmap_out or
                "139/tcp" in nmap_out or
                "445/tcp" in nmap_out
            ):
                nbt_output = nbt_scan(target)

            progress.advance(task, 3)

        # Option 4
        elif option == "4":

            ensure_tool("nmap")
            ensure_tool("whatweb")
            ensure_tool("nuclei")

            supplied_ports = (
                ports.split(",")
                if ports else None
            )

            services, nmap_out = nmap_scan(
                target,
                supplied_ports
            )

            progress.advance(task, 2)

            web_ports = extract_web_ports(
                nmap_out
            )

            if web_ports:

                web_findings = run_web_scans(
                    target,
                    web_ports
                )

            else:

                console.print(
                    "[yellow]No web services "
                    "detected. Skipping web "
                    "scans.[/yellow]"
                )

            progress.advance(task, 3)

        # Option 5
        elif option == "5":

            required_tools = [
                "masscan",
                "nmap",
                "nbtscan",
                "whatweb",
                "nuclei"
            ]

            for tool in required_tools:
                ensure_tool(tool)

            if use_nikto:
                ensure_tool("nikto")

            # Masscan only if ports not supplied
            if ports:

                console.print(
                    "[yellow]Using supplied ports. "
                    "Skipping Masscan.[/yellow]"
                )

                discovered = ports.split(",")

            else:

                console.print(
                    "[cyan]Running Masscan...[/cyan]"
                )

                discovered = masscan_scan(target)

            progress.advance(task)

            console.print(
                f"[green]Discovered Ports: "
                f"{','.join(discovered)}[/green]"
            )

            services, nmap_out = nmap_scan(
                target,
                discovered
            )

            progress.advance(task)

            # SMB scan
            if any(
                p in discovered
                for p in ["137", "139", "445"]
            ):
                nbt_output = nbt_scan(target)

            progress.advance(task)

            # Web scans
            web_ports = extract_web_ports(
                nmap_out
            )

            if web_ports:

                web_findings = run_web_scans(
                    target,
                    web_ports,
                    use_nikto
                )

            else:

                console.print(
                    "[yellow]No web services "
                    "detected. Skipping web "
                    "enumeration.[/yellow]"
                )

            progress.advance(task)

            progress.advance(task)

        else:

            console.print(
                "[red]Invalid Option[/red]"
            )
            return

    end_time = time.time()

    duration = time.strftime(
        "%H:%M:%S",
        time.gmtime(end_time - start_time)
    )

    report_file = save_report(
        target,
        services,
        nbt_output,
        web_findings
    )

    print_results(
        target,
        services,
        nbt_output,
        web_findings,
        duration,
        report_file
    )


if __name__ == "__main__":
    main()
