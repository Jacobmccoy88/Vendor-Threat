"""
Vendor Threat Intelligence Scanner
Local Flask app for scanning cybersecurity sources for vendor incidents/breaches.
"""

from flask import Flask, render_template, request, jsonify
from modules.scanner import VendorScanner
import json

app = Flask(__name__)
scanner = VendorScanner()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    vendor_name = data.get("vendor", "").strip()

    if not vendor_name:
        return jsonify({"error": "No vendor name provided"}), 400

    results = scanner.scan(vendor_name)
    return jsonify(results)


@app.route("/sources")
def sources():
    return jsonify(scanner.get_sources())


if __name__ == "__main__":
    print("🔍 Vendor Threat Intelligence Scanner")
    print("   Running at http://localhost:5000")
    app.run(debug=True, port=5000)