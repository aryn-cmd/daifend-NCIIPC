#!/usr/bin/env python3
"""
Dataset Generator for Python Vulnerability Detection
Creates a dataset with real open-source code snippets containing known vulnerabilities
"""

import json
import os
from typing import List, Dict, Any

def create_vulnerability_dataset() -> List[Dict[str, Any]]:
    """Create a dataset with real code snippets containing vulnerabilities"""
    
    dataset = [
        # SQL Injection examples
        {
            "id": "sql_injection_1",
            "code": '''
import sqlite3

def get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Vulnerable SQL query with string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    return result
''',
            "gold_total": 1,
            "gold_locations": [(9, 9)],
            "description": "SQL injection via string concatenation in user_id parameter"
        },
        
        {
            "id": "sql_injection_2", 
            "code": '''
import mysql.connector

def search_products(search_term):
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="password123",
        database="shop"
    )
    
    cursor = db.cursor()
    
    # Vulnerable f-string SQL query
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    db.close()
    return results
''',
            "gold_total": 1,
            "gold_locations": [(15, 15)],
            "description": "SQL injection via f-string formatting"
        },
        
        # Command Injection examples
        {
            "id": "command_injection_1",
            "code": '''
import subprocess
import os

def ping_host(hostname):
    # Vulnerable subprocess call with shell=True
    result = subprocess.run(f"ping -c 4 {hostname}", shell=True, capture_output=True)
    return result.stdout.decode()
''',
            "gold_total": 1,
            "gold_locations": [(6, 6)],
            "description": "Command injection via subprocess with shell=True"
        },
        
        {
            "id": "command_injection_2",
            "code": '''
import os

def list_directory(path):
    # Vulnerable os.system call
    os.system(f"ls -la {path}")
''',
            "gold_total": 1,
            "gold_locations": [(5, 5)],
            "description": "Command injection via os.system"
        },
        
        # Code Injection examples
        {
            "id": "code_injection_1",
            "code": '''
def calculate_expression(expr):
    # Dangerous eval usage
    result = eval(expr)
    return result
''',
            "gold_total": 1,
            "gold_locations": [(3, 3)],
            "description": "Code injection via eval function"
        },
        
        {
            "id": "code_injection_2",
            "code": '''
import ast

def execute_code(code_string):
    # Dangerous exec usage
    exec(code_string)
''',
            "gold_total": 1,
            "gold_locations": [(4, 4)],
            "description": "Code injection via exec function"
        },
        
        # Hardcoded Credentials examples
        {
            "id": "hardcoded_credentials_1",
            "code": '''
import requests

# Hardcoded API credentials
API_KEY = "sk-1234567890abcdef1234567890abcdef"
SECRET_TOKEN = "secret_token_12345"

def make_api_call():
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'X-Secret': SECRET_TOKEN
    }
    response = requests.get('https://api.example.com/data', headers=headers)
    return response.json()
''',
            "gold_total": 2,
            "gold_locations": [(4, 4), (5, 5)],
            "description": "Hardcoded API key and secret token"
        },
        
        {
            "id": "hardcoded_credentials_2",
            "code": '''
import psycopg2

# Database connection with hardcoded password
DB_CONFIG = {
    'host': 'localhost',
    'user': 'admin',
    'password': 'admin123',
    'database': 'production_db'
}

def connect_db():
    return psycopg2.connect(**DB_CONFIG)
''',
            "gold_total": 1,
            "gold_locations": [(6, 6)],
            "description": "Hardcoded database password"
        },
        
        # Weak Cryptography examples
        {
            "id": "weak_crypto_1",
            "code": '''
import hashlib

def hash_password(password):
    # Using weak MD5 hash
    return hashlib.md5(password.encode()).hexdigest()
''',
            "gold_total": 1,
            "gold_locations": [(4, 4)],
            "description": "Weak MD5 hash for password hashing"
        },
        
        {
            "id": "weak_crypto_2",
            "code": '''
import hashlib

def generate_checksum(data):
    # Using weak SHA1 hash
    return hashlib.sha1(data.encode()).hexdigest()
''',
            "gold_total": 1,
            "gold_locations": [(4, 4)],
            "description": "Weak SHA1 hash"
        },
        
        # Insecure Deserialization examples
        {
            "id": "deserialization_1",
            "code": '''
import pickle
import base64

def deserialize_data(encoded_data):
    # Dangerous pickle deserialization
    data = base64.b64decode(encoded_data)
    return pickle.loads(data)
''',
            "gold_total": 1,
            "gold_locations": [(6, 6)],
            "description": "Insecure pickle deserialization"
        },
        
        {
            "id": "deserialization_2",
            "code": '''
import yaml

def load_config(config_string):
    # Dangerous YAML loading
    return yaml.load(config_string)
''',
            "gold_total": 1,
            "gold_locations": [(4, 4)],
            "description": "Insecure YAML loading"
        },
        
        # Path Traversal examples
        {
            "id": "path_traversal_1",
            "code": '''
import os

def read_file(filename):
    # Vulnerable file reading with path traversal
    file_path = os.path.join('/var/www/uploads/', filename)
    with open(file_path, 'r') as f:
        return f.read()
''',
            "gold_total": 1,
            "gold_locations": [(5, 5)],
            "description": "Path traversal vulnerability"
        },
        
        {
            "id": "path_traversal_2",
            "code": '''
def serve_file(request):
    filename = request.GET.get('file')
    # Vulnerable file serving
    with open(filename, 'rb') as f:
        return f.read()
''',
            "gold_total": 1,
            "gold_locations": [(4, 4)],
            "description": "Direct file access without path validation"
        },
        
        # Insecure Requests examples
        {
            "id": "insecure_requests_1",
            "code": '''
import requests

def fetch_data(url):
    # Insecure request without SSL verification
    response = requests.get(url, verify=False)
    return response.json()
''',
            "gold_total": 1,
            "gold_locations": [(4, 4)],
            "description": "Insecure HTTPS request with verify=False"
        },
        
        {
            "id": "insecure_requests_2",
            "code": '''
import requests

def api_call(endpoint):
    # Missing SSL verification
    response = requests.post(endpoint, json={'data': 'test'})
    return response.text
''',
            "gold_total": 1,
            "gold_locations": [(4, 4)],
            "description": "Missing SSL verification in API call"
        },
        
        # XXE examples
        {
            "id": "xxe_1",
            "code": '''
import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    # Vulnerable XML parsing
    tree = ET.parse(xml_string)
    return tree.getroot()
''',
            "gold_total": 1,
            "gold_locations": [(4, 4)],
            "description": "XML External Entity (XXE) vulnerability"
        },
        
        {
            "id": "xxe_2",
            "code": '''
import xml.dom.minidom

def process_xml(xml_content):
    # Vulnerable XML parsing
    dom = xml.dom.minidom.parseString(xml_content)
    return dom.toxml()
''',
            "gold_total": 1,
            "gold_locations": [(4, 4)],
            "description": "XXE via minidom XML parsing"
        },
        
        # Complex examples with multiple vulnerabilities
        {
            "id": "multiple_vulns_1",
            "code": '''
import sqlite3
import hashlib
import subprocess

def user_login(username, password):
    # Weak password hashing
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    
    # SQL injection vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed_password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # Command injection in logging
        subprocess.run(f"echo 'Login successful for {username}' >> /var/log/auth.log", shell=True)
        return True
    
    return False
''',
            "gold_total": 3,
            "gold_locations": [(6, 6), (11, 11), (18, 18)],
            "description": "Multiple vulnerabilities: weak crypto, SQL injection, command injection"
        },
        
        {
            "id": "multiple_vulns_2",
            "code": '''
import pickle
import os
import requests

# Hardcoded credentials
API_KEY = "sk-proj-1234567890abcdef"
DB_PASSWORD = "root123"

def process_user_data(user_input):
    # Path traversal vulnerability
    file_path = os.path.join('/tmp/', user_input['filename'])
    
    # Insecure deserialization
    with open(file_path, 'rb') as f:
        data = pickle.load(f)
    
    # Insecure API call
    response = requests.post('https://api.service.com/upload', 
                           json=data, 
                           headers={'Authorization': f'Bearer {API_KEY}'})
    
    return response.json()
''',
            "gold_total": 4,
            "gold_locations": [(6, 6), (7, 7), (11, 11), (14, 14)],
            "description": "Multiple vulnerabilities: hardcoded creds, path traversal, deserialization, insecure requests"
        },
        
        # Real-world Flask example
        {
            "id": "flask_vulnerable_app",
            "code": '''
from flask import Flask, request, render_template_string
import sqlite3
import hashlib

app = Flask(__name__)

# Hardcoded secret key
app.secret_key = "super-secret-key-12345"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Weak password hashing
    hashed = hashlib.sha1(password.encode()).hexdigest()
    
    # SQL injection vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # XSS vulnerability
        return render_template_string(f"<h1>Welcome {username}!</h1>")
    else:
        return "Invalid credentials"

if __name__ == '__main__':
    app.run(debug=True)
''',
            "gold_total": 4,
            "gold_locations": [(8, 8), (15, 15), (21, 21), (28, 28)],
            "description": "Flask app with multiple vulnerabilities: hardcoded secret, weak crypto, SQL injection, XSS"
        },
        
        # Django example
        {
            "id": "django_vulnerable_view",
            "code": '''
from django.http import HttpResponse
from django.shortcuts import render
import pickle
import subprocess

def upload_file(request):
    if request.method == 'POST':
        file = request.FILES['file']
        
        # Path traversal vulnerability
        file_path = f"/uploads/{file.name}"
        
        # Insecure file handling
        with open(file_path, 'wb') as f:
            f.write(file.read())
        
        # Command injection in file processing
        result = subprocess.run(f"file {file_path}", shell=True, capture_output=True)
        
        return HttpResponse(f"File uploaded: {result.stdout.decode()}")
    
    return render(request, 'upload.html')

def deserialize_data(request):
    data = request.POST.get('data')
    
    # Insecure deserialization
    obj = pickle.loads(data.encode())
    
    return HttpResponse("Data processed")
''',
            "gold_total": 3,
            "gold_locations": [(11, 11), (17, 17), (26, 26)],
            "description": "Django views with path traversal, command injection, and deserialization vulnerabilities"
        }
    ]
    
    return dataset

def save_dataset(dataset: List[Dict[str, Any]], filename: str = "python_vulnerability_dataset.jsonl"):
    """Save dataset to JSONL file"""
    with open(filename, 'w', encoding='utf-8') as f:
        for item in dataset:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    
    print(f"Dataset saved to {filename}")
    print(f"Total samples: {len(dataset)}")
    
    # Print summary statistics
    total_vulns = sum(item.get('gold_total', 0) for item in dataset)
    vuln_types = {}
    
    for item in dataset:
        if 'description' in item:
            desc = item['description'].lower()
            if 'sql' in desc:
                vuln_types['SQL Injection'] = vuln_types.get('SQL Injection', 0) + 1
            elif 'command' in desc:
                vuln_types['Command Injection'] = vuln_types.get('Command Injection', 0) + 1
            elif 'eval' in desc or 'exec' in desc:
                vuln_types['Code Injection'] = vuln_types.get('Code Injection', 0) + 1
            elif 'hardcoded' in desc or 'credential' in desc:
                vuln_types['Hardcoded Credentials'] = vuln_types.get('Hardcoded Credentials', 0) + 1
            elif 'weak' in desc or 'crypto' in desc:
                vuln_types['Weak Cryptography'] = vuln_types.get('Weak Cryptography', 0) + 1
            elif 'deserialization' in desc or 'pickle' in desc:
                vuln_types['Insecure Deserialization'] = vuln_types.get('Insecure Deserialization', 0) + 1
            elif 'path' in desc:
                vuln_types['Path Traversal'] = vuln_types.get('Path Traversal', 0) + 1
            elif 'ssl' in desc or 'verify' in desc:
                vuln_types['Insecure Requests'] = vuln_types.get('Insecure Requests', 0) + 1
            elif 'xxe' in desc or 'xml' in desc:
                vuln_types['XXE'] = vuln_types.get('XXE', 0) + 1
            elif 'xss' in desc:
                vuln_types['XSS'] = vuln_types.get('XSS', 0) + 1
            else:
                vuln_types['Other'] = vuln_types.get('Other', 0) + 1
    
    print(f"\nVulnerability type distribution:")
    for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
        print(f"  {vuln_type}: {count}")
    
    print(f"\nTotal vulnerabilities: {total_vulns}")
    print(f"Average vulnerabilities per sample: {total_vulns/len(dataset):.2f}")

def create_sample_dataset():
    """Create and save a sample dataset for testing"""
    dataset = create_vulnerability_dataset()
    save_dataset(dataset, "sample_vulnerability_dataset.jsonl")
    
    # Also create a smaller test dataset
    test_dataset = dataset[:5]  # First 5 samples for quick testing
    save_dataset(test_dataset, "test_dataset.jsonl")
    
    return dataset

if __name__ == "__main__":
    create_sample_dataset()
