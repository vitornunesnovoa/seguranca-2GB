from flask import Flask, jsonify, request
from cvss import CVSS3
from json_to_string import json_to_cvss_string

app = Flask(__name__)


@app.route("/calculate-cvss", methods=["POST"])
def calculate_cvss():
    try:
        # Carrega o json informado na requisição
        data = request.get_json()
        # Move o valor da chave "vector" do json informado na requisição
        vector = json_to_cvss_string(data)
        # Instancia o objeto CVSS3 com o valor do vector
        metrics = CVSS3(vector)
        # Realiza o cálculo das pontuações(scores)
        # Exemplo:
        # scores = (6.8, 5.2, 2.7)
        scores = metrics.scores()
        # Realiza o cálculo das severidades(severities)
        # Exemplo:
        # severities = ("Medium", "Medium", "Medium")
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


if __name__ == "__main__":
    app.run(ssl_context=("cert.pem", "key.pem"))
