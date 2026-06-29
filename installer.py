
import shutil
import subprocess

TOOLS = {
    "nmap": "nmap",
    "masscan": "masscan",
    "nbtscan": "nbtscan",
    "nuclei": "nuclei",
    "whatweb": "whatweb",
    "nikto": "nikto"
}


def ensure_tool(tool):

    if shutil.which(tool):
        return True

    choice = input(
        f"[-] {tool} not found. Install? [Y/n]: "
    )

    if choice.lower() not in ["", "y", "yes"]:
        return False

    try:
        subprocess.run(
            ["sudo", "apt", "update"],
            check=True
        )

        subprocess.run(
            ["sudo", "apt", "install", "-y",
             TOOLS[tool]],
            check=True
        )

        return True

    except Exception as e:
        print(f"[-] Failed installing {tool}: {e}")
        return False

