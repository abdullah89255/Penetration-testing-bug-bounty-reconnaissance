# Penetration-testing-bug-bounty-reconnaissance
Great question 👍 You’re essentially asking:

**“How can I detect what technologies a website is running on, and how to know if those technologies or servers are vulnerable?”**

This is a very common step in **penetration testing / bug bounty reconnaissance**. Let’s break it down step by step with **details, tools, and methodology**.

---

# 🔎 Step 1: Identify Website Technologies (Tech Stack Fingerprinting)

Before you can check vulnerabilities, you need to know what the website is built on.

### ✅ Methods:

1. **HTTP Headers**

   * Look at response headers (`curl -I https://target.com` or BurpSuite).
   * Common signs:

     * `Server: Apache/2.4.41 (Ubuntu)`
     * `X-Powered-By: PHP/7.4`
     * `Via: Cloudflare`

2. **BuiltWith / Wappalyzer (Automation)**

   * Tools that fingerprint tech stack:

     * [Wappalyzer CLI](https://www.npmjs.com/package/wappalyzer)

       ```bash
       wappalyzer https://target.com
       ```
     * [BuiltWith](https://builtwith.com)

   These show CMS (WordPress, Joomla, Drupal), JS frameworks (React, Angular), server software, analytics tools, etc.

3. **CMS/Framework Detection**

   * `whatweb` (Kali tool)

     ```bash
     whatweb https://target.com
     ```
   * `cmseek` (CMS detection)
   * `droopescan` (Drupal, WordPress, Joomla scanning)

4. **Manual Inspection**

   * Look at page source → check comments, JS files (`/wp-content/`, `/drupal.js`) → reveals CMS/framework.
   * Check cookies → e.g. `PHPSESSID`, `ASP.NET_SessionId`.

---

# 🔎 Step 2: Identify Server & Infrastructure

Beyond the web app itself, find out what servers and services are exposed.

### ✅ Tools:

1. **Nmap (Port Scanning & Service Detection)**

   ```bash
   nmap -sV -p- target.com
   ```

   * Detects open ports and versions (Apache 2.4.41, OpenSSH 7.9, MySQL 5.7, etc.).

2. **Subdomain Enumeration (to find hidden servers)**

   * `subfinder -d target.com -o subdomains.txt`
   * `amass enum -d target.com`
   * `assetfinder target.com`

3. **DNS/Cloud Detection**

   * `dig`, `nslookup`, or tools like `dnsrecon` to check DNS records.
   * May reveal mail servers, CDN, hidden origin IPs.

---

# 🔎 Step 3: Check for Known Vulnerabilities

Now that you have **software names & versions**, you can check if they are vulnerable.

### ✅ Tools & Techniques:

1. **SearchSploit (local exploit DB on Kali)**

   ```bash
   searchsploit apache 2.4.41
   searchsploit wordpress 5.6
   ```

2. **NVD / CVE Database (Manual Research)**

   * [NVD](https://nvd.nist.gov/) → Search the version.
   * Example: "Apache 2.4.49 CVE" → reveals Path Traversal RCE.

3. **Vulnerability Scanners**

   * `nmap --script vuln target.com` (quick check)
   * `nikto -h https://target.com` (old webserver vulns)
   * `nuclei` (powerful template-based scanner)

     ```bash
     nuclei -u https://target.com -t cves/
     ```
   * `openvas` / `nessus` (enterprise-level scanners).

4. **Shodan / Censys (Internet-Wide Scan)**

   * Search the server IP in [Shodan](https://www.shodan.io/) → shows exposed services, vulnerabilities, CVEs.
   * Example: `"Apache/2.4.49" port:80` in Shodan search.

---

# 🔎 Step 4: Prioritize What’s Really Vulnerable

Not every outdated technology is exploitable. To confirm vulnerabilities:

* Match exact version numbers with CVEs.
* Test with **PoC scripts** (only in legal scope!).
* Check security advisories (vendor sites, GitHub issues, exploit-db).

---

# ⚡ Example Workflow (Full Process)

Let’s say target = `https://example.com`

1. Fingerprint technologies:

   ```bash
   whatweb https://example.com
   ```

   → Finds WordPress 5.5, Apache 2.4.49.

2. Scan server:

   ```bash
   nmap -sV -p- example.com
   ```

   → Finds OpenSSH 7.4, MySQL 5.7, Apache 2.4.49.

3. Check vulnerabilities:

   ```bash
   searchsploit apache 2.4.49
   searchsploit wordpress 5.5
   ```

   → Apache 2.4.49 (Path Traversal CVE-2021-41773).
   → WordPress 5.5 (XSS vulnerabilities).

4. Run nuclei scan:

   ```bash
   nuclei -u https://example.com -t cves/
   ```

   → Confirms CVE-2021-41773 is exploitable.

---

# 🛡️ Step 5: Fix / Remediation

If you’re the defender (Blue Team):

* Regularly update web servers & CMS.
* Hide version info (`ServerTokens Prod` in Apache).
* Use WAF (Cloudflare, ModSecurity).
* Perform routine vulnerability scanning.

---

✅ **In short:**

* Use `whatweb`, `wappalyzer`, and manual inspection → detect technologies.
* Use `nmap`, `nikto`, `subfinder` → detect servers and services.
* Use `searchsploit`, `nuclei`, `shodan` → map vulnerabilities.

---

👉 Do you want me to **make a ready-to-use Bash script** that automates all these steps (tech detection + scanning + vuln lookup) into one tool for your recon workflow?
