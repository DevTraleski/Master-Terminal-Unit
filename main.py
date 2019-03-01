from flask import Flask, request, jsonify
from Connector import Connector
from logging.config import dictConfig
import time
import datetime

#print(datetime.datetime.fromtimestamp(endTime).strftime('====== Result Time %S,%f')[:-3])


dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'ERROR',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)

connector = Connector()

@app.route("/search", methods=['GET', 'POST'])
def search():
	connector.startTime = time.time()

	token = request.headers.get('Authorization')
	req = request.form.get('req')
	gateway = request.form.get('gateway')

	if connector.checkToken(token) == False:
		return "Token expired or not valid"

	return connector.req(token, req, gateway)

@app.route("/response", methods=['GET', 'POST'])
def response():
	data = request.form.get('res')

	endTime = time.time() - connector.startTime
	print(datetime.datetime.fromtimestamp(endTime).strftime('Result Time: %S,%f')[:-3])

	return connector.receive(data)

@app.route("/getdata")
def getdata():
	return connector.returnData()

@app.route("/setup")
def setup():
	gateway = request.form.get('gateway')
	serial = request.form.get('serial')
	gnonce = request.form.get('gnonce')
	dtlsk = request.form.get('dtlsk')
	return connector.setup(gateway, serial, gnonce, dtlsk)

@app.route("/alert", methods=['GET', 'POST'])
def alert():
	if request.method == 'POST':
		print("Alert received")
		payload = request.form.get('alert')
		gw = request.form.get('gateway')
		connector.receiveAlert(payload, gw)
		return "Received"
	elif request.method == 'GET':
		token = request.headers.get('Authorization')
		if connector.checkToken(token) == False:
			return "Token expired or not valid"
		return connector.returnAlerts()
	return "Method not allowed"

if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'), host="0.0.0.0")
