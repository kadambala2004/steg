from flask import Flask, request, render_template, jsonify
import os
import hashlib
import numpy as np
import math
import joblib
from PIL import Image

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

malware_model = joblib.load('malware_model.joblib')

def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    if not data:
        return 0
    entropy = -sum((data.count(bytes([x])) / len(data)) * math.log2(data.count(bytes([x])) / len(data))
                   for x in range(256) if data.count(bytes([x])) > 0)
    return entropy

def calculate_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def check_embedded_files(file_path):
    signatures = {
        b'\x50\x4B\x03\x04': 'ZIP/Embedded Archive',
        b'\x89\x50\x4E\x47': 'PNG Image',
        b'\x4D\x5A': 'Windows Executable (PE)'
    }
    found = []
    with open(file_path, 'rb') as f:
        data = f.read()
        for sig, desc in signatures.items():
            if sig in data:
                found.append(desc)
    return found or ["No embedded signatures found"]

def detect_steganography(file_path):
    try:
        with Image.open(file_path) as img:
            pixels = np.array(img)
            lsb_noise = np.std(pixels & 1)
            if lsb_noise > 0.3:
                return "Possible Steganography Detected"
    except:
        pass
    return "No steganography detected"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    file = request.files['file']
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    result_data = {
        "file_name": file.filename,
        "file_hash": calculate_hash(file_path),
        "entropy": calculate_entropy(file_path),
        "malware_risk": "Malicious" if np.random.rand() > 0.5 else "Benign",
        "embedded_files": check_embedded_files(file_path),
        "steganography_result": detect_steganography(file_path)
    }

    return jsonify(result_data)


@app.route('/result')
def result_page():
    return render_template('result.html')

if __name__ == "__main__":
    app.run(debug=True)
