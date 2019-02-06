from flask import Flask, request, jsonify
from Validator import Validator

app = Flask(__name__)
app.config["SECRET_KEY"] = "9WjsiJ74/NcwpLm6MuCV9RLZygQh5V2v79Df8/QsaKQ="

validator = Validator()

@app.route("/search", methods=['POST'])
def search():
	isValid = validator.test(request.form.get('token'))
	if isValid == False:
		return "Token not valid!"
	
	return "Token valid, return search"

if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'), host="0.0.0.0")
