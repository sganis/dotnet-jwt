#!/usr/bin/env python3
# flask jwt server
import os
from flask import Flask, request, jsonify, make_response
import jwt
from functools import wraps

# creates Flask object
app = Flask(__name__)
# configuration
# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
app.config['SECRET_KEY'] = 'SECRET TO SIGN AND VERIFY JWT TOKENS'


def run(cmd, timeout=300):
	cmd = cmd.replace('\n','')
	# print(f'CMD: {cmd}')
	p = subprocess.run(cmd.replace('\n',' ').split(), 
			encoding='utf8', timeout=timeout, 
			stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout = p.stdout.strip()
	stderr = p.stderr.strip()
	return stdout, stderr


# decorator for verifying the JWT
def jwt_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		# jwt is passed in the request header
		if ('Authorization' in request.headers 
			and request.headers['Authorization'].startswith('Bearer ')):
			token = request.headers['Authorization'].split()[1]
		# return 401 if token is not passed
		if not token:
			return jsonify({'message' : 'Unauthorized'}), 401
		try:
			# decoding the payload to fetch the stored details
			data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
			print(data)
			# check if user is valid in database, throw if not 
			username = data['id']
		except Exception as ex:
			print(ex)
			return jsonify({'message' : 'Unauthorized'}), 401
		# returns the current logged in users contex to the routes
		return f(username, *args, **kwargs)
	return decorated


@app.route('/fs', methods =['GET'])
@jwt_required
def get_all_files(user):
	print(f'current user: {user}')
	output = []
	for file in os.listdir('/'):
		stat = os.lstat(os.path.join('/', file))
		output.append({
			'name': file,
			'stat' : stat
		})

	return jsonify(output)



if __name__ == "__main__":
	app.run(host='0.0.0.0', debug = True)
