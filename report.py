from datetime import datetime
import os

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)


def save_report(target,
                services,
                nbt_output,
                web_findings):

    filename = (
        f"{REPORT_DIR}/"
        f"{target}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )

    with open(filename, "w") as f:

        f.write("=" * 60 + "\n")
        f.write(f"TARGET : {target}\n")
        f.write("=" * 60 + "\n\n")

        # Open Services
        f.write("[OPEN SERVICES]\n\n")

        if services:
            for service in services:
                f.write(service + "\n")
        else:
            f.write("No services found.\n")

        # NetBIOS
        if nbt_output:
            f.write("\n[NETBIOS]\n")
            f.write(nbt_output + "\n")

        # Web Findings
        if web_findings:
            f.write("\n[WEB FINDINGS]\n")

            for item in web_findings:
                if item.strip():
                    f.write(item + "\n")

    return filename
