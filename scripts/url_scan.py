import requests
import json

def scan_url(scan_url):

  url = "https://www.virustotal.com/api/v3/urls"

  payload = { "url": scan_url }
  # payload = scan_url
  headers = {
      "accept": "application/json",
      "x-apikey": "VIRUS_TOTAL_API",
      "content-type": "application/x-www-form-urlencoded"
  }

  response = requests.post(url, data=payload, headers=headers)

  # print(response.text)
  response_data = json.loads(response.text)

  scan_id = response_data["data"]["id"]

  return scan_id


def get_scan_report(scan_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"

    headers = {"accept": "application/json"}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        # scan_report = response.json()
        print(response.text)
        # return scan_report
        # print(scan_report)
    else:
        print(f"Error retrieving scan report: {response.status_code}")
        return None

 

def main():
  """Scans a file or URL and displays the scan results."""

  # Get the file path or URL to be scanned.
  file_path_or_url = input('Enter the file path or URL to be scanned: ')

  # Scan the file or URL.
  if file_path_or_url.startswith('http://') or file_path_or_url.startswith('https://'):
    # scan_results = scan_url(file_path_or_url)
    scan_id = scan_url(file_path_or_url)
    get_scan_report(scan_id)
#   # else:
#     # scan_results = scan_file(file_path_or_url)

#   # Display the scan results.
  # print(json.dumps(scan_results, indent=4))

if __name__ == '__main__':
  main()
