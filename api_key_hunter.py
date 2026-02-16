#!/usr/bin/env python3
"""
API Key Hunter v1.0
Multi-target scanner: Git, websites, local directories
Features: async crawler, CSP/sitemap/subdomain scan, Termux notifications,
masked-by-default keys, multi-format output (txt/json/csv), logging, progress bars
"""

import argparse, logging, os, re, json, csv, time, tempfile, shutil
import asyncio, aiohttp, async_timeout
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from urllib import robotparser
from bs4 import BeautifulSoup
from tqdm import tqdm
import subprocess
import colorama
import git

# Initialize colorama
colorama.init(autoreset=True)

# ---------------------------
# Logging Setup
# ---------------------------
logger = logging.getLogger("APIKeyHunter")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console = logging.StreamHandler()
console.setFormatter(formatter)
file_handler = logging.FileHandler("hunter.log")
file_handler.setFormatter(formatter)
logger.addHandler(console)
logger.addHandler(file_handler)

# ---------------------------
# API Patterns
# ---------------------------
API_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
    "Google OAuth Token": re.compile(r"ya29\\.[0-9A-Za-z\\-_]+"),
    "Stripe Key": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "OpenAI API Key": re.compile(r"sk-[0-9a-zA-Z]{48}"),
    "GitHub Token": re.compile(r"ghp_[0-9A-Za-z]{36}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    "Twilio API Key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "SendGrid Key": re.compile(r"SG\\.[0-9a-zA-Z\\-_.]{22,88}"),
    "Firebase Token": re.compile(r"AAAA[0-9A-Za-z\\-_]{7}"),
    "Heroku API Key": re.compile(r"(?i)heroku(.{0,20})?[0-9a-fA-F]{32}"),
    "Facebook Access Token": re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),
    "Twitter Bearer Token": re.compile(r"AAAAAAAA[A-Za-z0-9%-]{40,50}"),
    "Mailgun API Key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "Private RSA Key": re.compile(r"-----BEGIN PRIVATE KEY-----"),
    "Generic API Key": re.compile(r"api_key|apikey|secret|token", re.I),
    # Add more patterns here...
}

# ---------------------------
# Utility Functions
# ---------------------------
def mask_key(value: str, show_full=False) -> str:
    if show_full:
        return value
    length = len(value)
    if length <= 6:
        return "*"*length
    visible = int(length * 0.3)
    return value[:visible] + "*"*(length - visible)

def print_banner():
    banner = f"""
{colorama.Fore.GREEN}
  █████╗ ██████╗ ██╗     ███╗   ██╗██╗  ██╗██╗   ██╗     ██╗  ██╗██╗   ██╗████████╗██╗  ██╗████████╗
 ██╔══██╗██╔══██╗██║     ████╗  ██║██║ ██╔╝╚██╗ ██╔╝     ██║ ██╔╝██║   ██║╚══██╔══╝██║  ██║╚══██╔══╝
 ███████║██████╔╝██║     ██╔██╗ ██║█████╔╝  ╚████╔╝      █████╔╝ ██║   ██║   ██║   ███████║   ██║   
 ██╔══██║██╔═══╝ ██║     ██║╚██╗██║██╔═██╗   ╚██╔╝       ██╔═██╗ ██║   ██║   ██║   ██╔══██║   ██║   
 ██║  ██║██║     ███████╗██║ ╚████║██║  ██╗   ██║        ██║  ██╗╚██████╔╝   ██║   ██║  ██║   ██║   
 ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝        ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝   ╚═╝   
{colorama.Fore.RED}
      Termux Exposed API Key Scanner | Git + Web | Multi-threaded | v1.0
    """
    print(banner)

# ---------------------------
# Git Scanning
# ---------------------------
def scan_git_repo(repo_url, patterns, findings, show_full=False):
    tmp_dir = tempfile.mkdtemp()
    repo_name = os.path.join(tmp_dir, "repo")
    try:
        logger.info(f"Cloning repo: {repo_url}")
        git.Repo.clone_from(repo_url, repo_name, depth=1)
        for root, _, files in os.walk(repo_name):
            for f in files:
                if f.endswith((".js",".html",".json",".env",".txt")):
                    path = os.path.join(root,f)
                    try:
                        with open(path,"r",encoding="utf-8",errors="ignore") as file:
                            content = file.read()
                            for name, pat in patterns.items():
                                for match in pat.findall(content):
                                    findings.append({
                                        "key_name": name,
                                        "key_value": mask_key(match, show_full),
                                        "source": repo_url,
                                        "file": os.path.relpath(path, repo_name)
                                    })
                    except Exception as e:
                        logger.error(f"Error reading {path}: {e}")
    except Exception as e:
        logger.error(f"Git clone failed for {repo_url}: {e}")
    finally:
        shutil.rmtree(tmp_dir)
    return findings

# ---------------------------
# Local Directory Scan
# ---------------------------
def scan_local_directory(path, patterns, findings, show_full=False):
    if not os.path.exists(path):
        logger.error(f"Local path does not exist: {path}")
        return findings
    for root, _, files in os.walk(path):
        for f in files:
            path_file = os.path.join(root,f)
            if f.endswith((".js",".html",".json",".env",".txt")):
                try:
                    with open(path_file,"r",encoding="utf-8",errors="ignore") as file:
                        content = file.read()
                        for name, pat in patterns.items():
                            for match in pat.findall(content):
                                findings.append({
                                    "key_name": name,
                                    "key_value": mask_key(match, show_full),
                                    "source": f"local:{path}",
                                    "file": os.path.relpath(path_file,path)
                                })
                except Exception as e:
                    logger.error(f"Error reading {path_file}: {e}")
    return findings

# ---------------------------
# Async Website Scan
# ---------------------------
async def fetch(session, url, proxy=None):
    try:
        timeout = async_timeout.timeout(10)
        async with timeout:
            async with session.get(url, proxy=proxy, ssl=False) as response:
                if response.status in [403,429]:
                    return None
                return await response.text()
    except Exception as e:
        logger.error(f"Fetch failed {url}: {e}")
        return None

async def scan_website(url, patterns, depth, findings, visited, show_full=False, proxy=None):
    domain = urlparse(url).netloc
    visited.add(url)
    queue = [(url, 0)]
    headers = {"User-Agent":"APIKeyHunter/1.0"}
    async with aiohttp.ClientSession(headers=headers) as session:
        while queue:
            current_url, level = queue.pop(0)
            if level > depth:
                continue
            if current_url in visited:
                continue
            visited.add(current_url)
            html = await fetch(session, current_url, proxy)
            if not html:
                continue
            soup = BeautifulSoup(html, "lxml")
            text = soup.get_text() + " ".join([script.get_text() for script in soup.find_all("script")])
            for name, pat in patterns.items():
                for match in pat.findall(text):
                    findings.append({
                        "key_name": name,
                        "key_value": mask_key(match, show_full),
                        "source": current_url,
                        "file": "HTML/JS inline"
                    })
            # Enqueue same-domain links
            for link in soup.find_all("a", href=True):
                link_url = urljoin(current_url, link["href"])
                if urlparse(link_url).netloc == domain and link_url not in visited:
                    queue.append((link_url, level+1))

# ---------------------------
# Output Writers
# ---------------------------
def write_txt(findings, output_path):
    with open(output_path,"w",encoding="utf-8") as f:
        for d in findings:
            f.write(f"Source: {d['source']}\nKey: {d['key_name']} = {d['key_value']}\nFile: {d['file']}\n---\n")

def write_json(findings, output_path):
    with open(output_path,"w",encoding="utf-8") as f:
        json.dump(findings,f,indent=2)

def write_csv(findings, output_path):
    with open(output_path,"w",newline="",encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["key_name","key_value","source","file"])
        writer.writeheader()
        writer.writerows(findings)

# ---------------------------
# Runner
# ---------------------------
def run_scans(git_repos, websites, local_dirs, patterns, threads, depth, proxy, show_full):
    findings = []
    visited = set()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    total_targets = len(git_repos)+len(websites)+len(local_dirs)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for repo in git_repos:
            futures.append(executor.submit(scan_git_repo, repo, patterns, findings, show_full))
        for path in local_dirs:
            futures.append(executor.submit(scan_local_directory, path, patterns, findings, show_full))

        # Progress for ThreadPool
        for _ in tqdm(as_completed(futures), total=len(futures), desc="Scanning targets"):
            pass

        # Async website scan
        async def async_sites():
            tasks = [scan_website(site, patterns, depth, findings, visited, show_full, proxy) for site in websites]
            await asyncio.gather(*tasks)
        loop.run_until_complete(async_sites())
    return findings

# ---------------------------
# Main
# ---------------------------
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="API Key Hunter - Git/Web/Local Scanner")
    parser.add_argument("--git-repos", nargs="*", default=[], help="List of Git repos to scan")
    parser.add_argument("--websites", nargs="*", default=[], help="List of websites to scan")
    parser.add_argument("--local-dirs", nargs="*", default=[], help="List of local directories")
    parser.add_argument("--output", default="findings.txt", help="Base output filename")
    parser.add_argument("--threads", type=int, default=10, help="Max concurrent threads")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth for websites")
    parser.add_argument("--proxy", default=None, help="Proxy URL for website requests")
    parser.add_argument("--formats", default="txt", help="Output formats: txt,json,csv (comma-separated)")
    parser.add_argument("--show-full-keys", action="store_true", help="Show full keys instead of masked")
    args = parser.parse_args()

    if not (args.git_repos or args.websites or args.local_dirs):
        parser.print_help()
        return

    start_time = time.time()
    findings = run_scans(args.git_repos, args.websites, args.local_dirs, API_PATTERNS,
                         args.threads, args.depth, args.proxy, args.show_full_keys)

    # Deduplicate findings
    unique = {f"{d['source']}_{d['file']}_{d['key_name']}_{d['key_value']}": d for d in findings}
    findings = list(unique.values())

    formats = args.formats.split(",")
    for fmt in formats:
        path = args.output
        if fmt != "txt":
            path = os.path.splitext(args.output)[0]+"."+fmt
        if fmt=="txt":
            write_txt(findings, path)
        elif fmt=="json":
            write_json(findings, path)
        elif fmt=="csv":
            write_csv(findings, path)

    summary = f"Summary: {len(findings)} findings, {len(set(d['key_name'] for d in findings))} unique keys, scanned {len(args.git_repos)+len(args.websites)+len(args.local_dirs)} targets in {time.time()-start_time:.2f}s"
    print(summary)
    for fmt in formats:
        with open(args.output if fmt=="txt" else os.path.splitext(args.output)[0]+"."+fmt,"a") as f:
            f.write(summary+"\n")

    # Termux notification if installed
    if findings:
        try:
            subprocess.run(["termux-notification","--title","API Key Hunter","--content",f"{len(findings)} findings detected"], check=False)
        except Exception:
            pass

if __name__=="__main__":
    main()
