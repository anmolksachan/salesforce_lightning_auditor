# Salesforce Aura Auditing Tool

**Salesforce Aura Auditing Tool** is a Python-based utility designed to identify and exploit potential data exposure vulnerabilities on Salesforce sites using the Aura framework. This tool leverages the permissions of an unauthenticated "guest user" to enumerate and dump accessible Salesforce objects, records, and even files.

Forked from `poc_salesforce_lightning` by moniik

-----

## 🚀 Features

  * **Vulnerability Check**: Quickly scans a target Salesforce site for a misconfigured Aura endpoint that could be vulnerable to guest user access.
  * **Object Enumeration**: Discovers and lists all standard and custom Salesforce objects that are publicly accessible.
  * **Data Dumping**: Dumps record data from specified or all accessible objects. It supports paginated dumping for large data sets.
  * **Record Details**: Fetches and displays the full details of a specific record by its ID.
  * **File Download**: Automatically downloads files from `ContentDocument` and `Document` objects, if they are accessible.
  * **Proxy Support**: All traffic can be routed through an HTTP/SOCKS proxy for analysis and debugging with tools like Burp Suite.
  * **Organized Output**: Dumps data into a structured directory named after the target URL, with separate JSON files for each object.

-----

## 🔧 Prerequisites

  * **Python 3.x**: This tool is built and tested with Python 3.
  * **`requests` Library**: This is the only external dependency. You can install it using `pip`.

<!-- end list -->

```bash
pip install requests
```

-----

## 📦 Installation

1.  Clone this repository or download the script directly.

    ```bash
    git clone https://github.com/anmolksachan/salesforce_lightning_auditor.git
    cd salesforce_lightning_auditor
    ```

2.  Install the required Python library.

    ```bash
    pip install requests
    ```

-----

## 📝 Usage

The tool is executed from the command line and uses a variety of arguments to control its behavior.

### ⚠️ Basic Syntax

```bash
python salesforce_auditor.py -u <target_url> [options]
```

### 🔍 Vulnerability Check

To simply check if a site has a vulnerable Aura endpoint, use the `-c` or `--check` flag.

```bash
python salesforce_auditor.py -u https://mycompany.my.site.com/ -c
```

### 📃 List All Accessible Objects

To get a list of all Salesforce objects that the guest user can access, use the `-l` or `--listobj` flag.

```bash
python salesforce_auditor.py -u https://mycompany.my.site.com/ -l
```

This will output a list of all standard objects (e.g., `User`, `Account`) and custom objects (e.g., `Custom_Object__c`) found.

### 🕵️ Dump Specific Objects

Use the `-o` or `--objects` flag followed by one or more object names to dump data from them. This command outputs the first page of records directly to the console.

```bash
python salesforce_auditor.py -u https://mycompany.my.site.com/ -o User Account
```

### 💾 Dump All Accessible Objects to Files

The `-d` or `--dump` flag is the most powerful option, as it will attempt to dump every single accessible object. A new directory will be created in the current working directory, named after the target URL, and each object's data will be saved as a separate JSON file.

  * **Standard Dump**: Dumps the first page of records for all accessible objects.

    ```bash
    python salesforce_auditor.py -u https://mycompany.my.site.com/ -d
    ```

  * **Full Dump (with Pagination)**: To retrieve all records, including those on subsequent pages, use the `--full` flag in conjunction with `-d`.

    ```bash
    python salesforce_auditor.py -u https://mycompany.my.site.com/ -d --full
    ```

  * **Skip Existing Objects**: If a dump was interrupted, you can resume it by using the `--skip` flag to avoid re-dumping objects that already have a corresponding JSON file.

    ```bash
    python salesforce_auditor.py -u https://mycompany.my.site.com/ -d --skip
    ```

### 📄 Dump a Single Record

To view the full details of a specific record, use the `-r` or `--record_id` flag.

```bash
python salesforce_auditor.py -u https://mycompany.my.site.com/ -r 003B000000y81J8IAI
```

### 🌐 Using a Proxy

To route all tool traffic through a local proxy (like Burp Suite for further analysis), use the `-p` or `--proxy` flag.

```bash
python salesforce_auditor.py -u https://mycompany.my.site.com/ -d --proxy http://127.0.0.1:8080
```

-----

## 🛠️ How It Works

This tool targets a known vulnerability in the **Salesforce Aura framework** related to the **guest user profile**. The Aura framework is a UI framework used to build single-page applications in Salesforce, and it includes endpoints that can be configured to be accessible without authentication.

  * **Guest User Privileges**: Salesforce sites often have a "guest user" profile for unauthenticated visitors. While these profiles have strict security defaults, administrators can grant them read access to specific objects and fields.
  * **Vulnerable Endpoint**: The tool identifies a specific Aura endpoint (`/s/aura`) that, when misconfigured, can be used to query the underlying Salesforce database.
  * **Exploitation**: By crafting specific JSON payloads and sending them to this endpoint, the tool can trick the application into revealing metadata and records that the guest user has been granted access to.

-----

## ⚖️ Disclaimer

This tool is intended for **authorized security testing and auditing purposes only**. Unauthorized access to any computer system or network is illegal. The developer of this tool is not responsible for any misuse or damage caused by its use. Users are responsible for complying with all applicable laws and regulations in their jurisdiction. Always obtain explicit permission from the site owner before conducting any security tests.

-----
