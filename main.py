from flask import Flask, render_template, request
import requests
import os
import json

app = Flask(__name__)

def scan_file(file_path):
  url = "https://www.virustotal.com/api/v3/files"

  files = {'file': open(file_path, 'rb')}
  headers = {
      "accept": "application/json",
      "x-apikey": "057e7f0c958c5dc0e3683ff3cbe9d1274bfeb3d3c44f892c2e7849612b5e7cf3"
  }

  response = requests.post(url, files=files, headers=headers)

  # print(response.text)
  response_data = json.loads(response.text)

  scan_id = response_data["data"]["id"]

  return scan_id


def scan_url(scan_url):
  url = "https://www.virustotal.com/api/v3/urls"

  payload = { "url": scan_url }
  headers = {
      "accept": "application/json",
      "x-apikey": "057e7f0c958c5dc0e3683ff3cbe9d1274bfeb3d3c44f892c2e7849612b5e7cf3",
      "content-type": "application/x-www-form-urlencoded"
  }

  response = requests.post(url, data=payload, headers=headers)

  # print(response.text)
  response_data = json.loads(response.text)

  scan_id = response_data["data"]["id"]

  return scan_id

    

def get_scan_report(scan_id):
    # Your existing code for getting scan report
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": "057e7f0c958c5dc0e3683ff3cbe9d1274bfeb3d3c44f892c2e7849612b5e7cf3"
    }
    response = requests.get(url, headers=headers)
    return response.text  # Return the scan report as a string
    # return response.json()
    # response = json.loads(response.text)
    # return response["data"]["attributes"]["results"]

# def format_scan_report(scan_report):
#     formatted_report = json.dumps(scan_report, indent=4)
#     return formatted_report



@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'submit_file' in request.form:
            file_path_or_url = handle_uploaded_file(request.files['file_path'])
            scan_id = scan_file(file_path_or_url)
        elif 'submit_url' in request.form:
            file_path_or_url = request.form['url']
            scan_id = scan_url(file_path_or_url)

        scan_report = get_scan_report(scan_id)
        return render_template('index.html', scan_report=scan_report)

    return render_template('index.html')

def handle_uploaded_file(file):
    upload_folder = 'uploads'
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, file.filename)
    file.save(file_path)
    return file_path


if __name__ == '__main__':
    app.run(debug=True)
