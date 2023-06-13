from flask import Flask, jsonify, request
from cvss import CVSS3
from json_to_string import json_to_cvss_string

app = Flask(__name__)

@app.route('/calculate-cvss', methods=['GET'])
def calculate_cvss():
    try:
        data = request.get_json()
        vector = json_to_cvss_string(data)
        metrics = CVSS3(vector)
        scores = metrics.scores()
        severities = metrics.severities()
        result = {
            "base_score": scores[0],
            "temporal_score": scores[1],
            "environmental_score": scores[2],
            "base_severity": severities[0],
            "temporal_severity": severities[1],
            "environmental_severity": severities[2],
        }
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(ssl_context=("cert.pem", "key.pem"))