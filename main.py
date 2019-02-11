from flask import Flask, request, jsonify
from Connector import Connector

app = Flask(__name__)

connector = Connector()

@app.route("/search", methods=['GET', 'POST'])
def search():
	token = request.headers.get('Authorization')
	req = request.form.get('req')
	gateway = request.form.get('gateway')

	if connector.checkToken(token) == False:
		return "Token expired or not valid"

	return connector.req(token, req, gateway)

if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'), host="0.0.0.0")
