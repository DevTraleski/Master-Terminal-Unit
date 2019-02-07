from flask import Flask, request, jsonify
from Connector import Connector

app = Flask(__name__)
app.config["SECRET_KEY"] = "9WjsiJ74/NcwpLm6MuCV9RLZygQh5V2v79Df8/QsaKQ="

connector = Connector()

@app.route("/search", methods=['POST'])
def search():
	if connector.checkToken(request.form.get('token')) == False:
		return "Token expired"	
	return connector.req("GetInfo", request.form.get('gateway'))

if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'), host="0.0.0.0")
