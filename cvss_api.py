from flask import Flask, jsonify, request
from cvss import CVSS3

app = Flask(__name__)

@app.route('/calculate-cvss', methods=['POST'])
def calculate_cvss():
    # Carrega o json informado na requisição
    data = request.json
    # Move o valor da chave "vector" do json informado na requisição
    vector = data.get("vector")
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
        "base_severitie": severities[0],
        "temporal_severitie": severities[1],
        "environmental_severitie": severities[2],
    }

    return jsonify(result)

if __name__ == '__main__':
    app.run()