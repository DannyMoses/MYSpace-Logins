from flask import Flask, request, session, render_template
from itsdangerous import URLSafeTimedSerializer
import bcrypt, requests
import MySQLdb

import logging, json, re, smtplib
from datetime import date
from config import CONFIG

import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
#import asyncio

#sender_email = "ubuntu@myspace-logins-1.c.winged-sol-258623.internal" # Domain not recognized
#sender_email = "fatyoshi@myspace-email.cloud.compas.cs.stonybrook.edu" # Domain not recognized
sender_email = "fatyoshienthusiasts@gmail.com"

app = Flask(__name__)

app.config["SECURITY_PASSWORD_SALT"] = "fatbirdo"
app.config["SECRET_KEY"] = "fatyoshi"

db = MySQLdb.connect(
	host=CONFIG["mysql_server"],
	port=CONFIG["mysql_port"],
	user=CONFIG["mysql_usr"],
	passwd=CONFIG["mysql_pwd"],
	db=CONFIG["mysql_db"]
)

#cursor = db.cursor()

EMAIL_REGEX = re.compile(r"([A-Z0-9_.+-]+@[A-Z0-9-]+.[A-Z0-9-.]+)", re.IGNORECASE)

#sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))

# Setup logging
if __name__ != '__main__':
	gunicorn_logger = logging.getLogger('gunicorn.error')
	app.logger.handlers = gunicorn_logger.handlers
	app.logger.setLevel(gunicorn_logger.level)

# Email validation
def gen_token(email):
	serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
	return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])

def confirm_token(token, expiration=10000):
	serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
	try:
		email = serializer.loads(
				token,
				salt=app.config["SECURITY_PASSWORD_SALT"],
				max_age=expiration
				)
	except:
		return False

	return email

# Fetch data from database
def get_user(user, cursor):
	sql = "SELECT * FROM users WHERE username=%s LIMIT 1"
	#app.logger.debug("check_user SQL: " + sql)
	#print("SQL:", sql)
	db.commit()
	cursor.execute(sql, (user,))
	row = cursor.fetchone()

	app.logger.debug("Result: ")
	app.logger.debug(str(row))

	if not row:
		return None
	else:
		user_data = {
			"username": row[0],
			"email": row[1],
			"password_hash": row[2],
			"validated": row[3]
		}
		return user_data

#async def send_email_helper(message):
#	try:
#		response = sg.send(message)
#		if response.stats_cose < 300:
#			print("Email processed, response.body, response.status_code")
#	except Exception as e:
#		print(str(e))
#
#@asyncio.coroutine
#def send_email(message):
#	asyncio.async(send_email_helper(message))

def check_user(user, cursor):
	sql = "SELECT username FROM users WHERE username=%s LIMIT 1"
	#app.logger.debug("check_user SQL: " + sql)
	#print("SQL:", sql)
	db.commit()
	cursor.execute(sql, (user,))
	row = cursor.fetchone()

	app.logger.debug("Result: ")
	app.logger.debug(str(row))

	if not row or user != row[0]:
		return False
	else:
		return False

def check_email(email, cursor):
	sql = "SELECT * FROM users WHERE email=%s"
	#app.logger.debug("check_email SQL: {} email: {}".format(sql, email))
	db.commit()
	cursor.execute(sql, (email,))
	row = cursor.fetchone()

	app.logger.debug("Result: ")
	app.logger.debug(row)

	if row is None or len(row) == 0:
		return False
	else:
		return True

def is_validated(user, cursor):
	sql = "SELECT validated FROM users WHERE username = %s LIMIT 1"
	#app.logger.debug("is_validated SQL: " + sql)
	db.commit()
	cursor.execute(sql, (user,))
	row = cursor.fetchone()

	app.logger.debug("Result: ")
	app.logger.debug(row)

	if not row:
		return False
	else:
		return row[0] == 1

def get_pwhash(user, cursor):
	sql = "SELECT password_hash FROM users where username = %s"
	#app.logger.debug("check_pwhash SQL: " + sql)
	db.commit()
	cursor.execute(sql, (user,))
	row = cursor.fetchone()

	app.logger.debug("Result: ")
	app.logger.debug(row)

	if not row:
		return None
	else:
		return row['password_hash']

# Reset
@app.route('/reset_logins', methods=["POST"])
def reset():
	#print("/RESET_LOGINS() CALLED")
	app.logger.warning("/RESET_LOGINS() CALLED")

	cursor = db.cursor()
	#cursor.execute("TRUNCATE TABLE users")
	cursor.execute("DELETE FROM users")
	db.commit()
	cursor.close()
	return { "status": "OK" }, 200

# Adduser
@app.route('/adduser', methods=["POST"])
def add_user():
	#return { "status" : "OK" }, 200
	#print(80*'=')
	#print("/ADDUSER() CALLED")
	data = request.json
	#print("DATA: ", str(data))
	app.logger.debug("/adduser data: " + json.dumps(data))

	if data is None:
		#print("error: DATA IS NONE")
		app.logger.info("/adduser no data specified")
		return { "status" : "error" , "error": "No data specified" }, 400

	if "username" not in data or "password" not in data or "email" not in data:
		#print("error: IMPROPER DATA")
		app.logger.info("/adduser not all data fields found")
		return { "status" : "error", "error": "Not all data fields were found" }, 400

	uname = data["username"]

	email = data["email"]
	res = EMAIL_REGEX.match(data['email'])

	if res == None:
		#print("error: BAD EMAIL REGEX MATCH")
		return { "status" : "error", "error" : "Not a valid email address" }, 400

	cursor = db.cursor()
#	if check_email(email, cursor):
#		print("error: DATABASE CHECK EMAIL FAILED")
#		return { "status" : "error", "error": "Email already in use" }, 400
#
#	app.logger.debug("/adduser email {} check passed".format(data['email']))
#
#	if check_user(uname, cursor):
#		print("error: DATABASE CHECK USERNAME FAILED")
#		return { "status" : "error", "error": "Username taken" }, 400
#
#	app.logger.debug("/adduser user {} check passed".format(data['username']))

	# Hash + salt password
	hashed = bcrypt.hashpw(data["password"].encode('utf8'), bcrypt.gensalt(5))
	hashed = hashed.decode('utf-8')

	# Try to insert user in database
	# Inform user if username/email is already used
	try:
		sql = "INSERT IGNORE INTO users (username, email, password_hash) VALUES (%s, %s, %s)"
		#print(type(hashed))
		val = (data['username'], data['email'], hashed)

		cursor.execute(sql, val)
		db.commit()

		if cursor.rowcount == 0:
			error = "{} <{}> already in use".format(data['username'], data['email'])
			#print("/adduser {} <{}> not unique".format(data['username'], data['email']))
			app.logger.info("/adduser {} <{}> not unique".format(data['username'], data['email']))
			return { "status" : "error", "error": error }, 400

		# Check email is in database
		#if check_email(data['email'], cursor):
		#	app.logger.debug("/adduser {} <{}> found in database".format(data['username'], data['email']))
		#else:
		#	app.logger.debug("/adduser {} <{}> not in database".format(data['username'], data['email']))
	finally:
#		if cursor.rowcount == 0:
#			print("SQL ERROR ENCOUNTERED")
#			return { "status" : "error" , "error" : "invalid username or email" }, 400
		cursor.close()
		#print("transaction done")

	# Send verification email
	# Delete database entry if email sending failed
	token = gen_token(data['email'])
	#print("SENDING EMAIL")
#	msg = Mail(
#		from_email=sender_email,
#		to_emails=data['email'],
#		subject="Your Moses&YangSpace Activation Key",
#		html_content="validation key: &lt;" + token + "&gt;")
#
#	try:
#		sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
#		response = sg.send(msg)
#		print("EMAIL RESPONSE", response.status_code)
#	except Exception as e:
#		print(str(e))

	email_json = {
		"key": CONFIG['email_key'],
		"from": sender_email,
		"to": data['email'],
		"subject": "Your Moses&YangSpace Activation Key",
		"body": "validation key: <" + token + ">",
	}

	r = requests.post("http://" + CONFIG["email_ip"] + "/send_email", json=email_json )

	# Send email. If error, delete database entry and return
	app.logger.info("Send email status code: {}".format(r.status_code))
	app.logger.debug(r.content)
	if r.status_code != 200:
		cursor = db.cursor()
		try:
			sql = "DELETE FROM users WHERE username=%s"
			cursor.execute(sql, (data['username'],))
			db.commit()
		finally:
			cursor.close()

		if r.status_code == 488:
			app.logger.warning("Validation email refused by recipient")
			return { "status": "error", "error": "Email address could not be sent." }, 400
		if r.status_code == 400:
			app.logger.error("/send_email request missing POST parameters")
			return { "status": "error", "error": "Problems sending email. Contact a developer." }, 500
		if r.status_code == 500:
			app.logger.error("Validation email could not be sent")
			return { "status": "error", "error": "Problems sending email. Contact a developer." }, 500

	# Create user profile in profiles service
	r = requests.post("http://" + CONFIG["profiles_ip"] + "/user", json= { "username" : data['username'],
		"email" : data['email'] } )
	app.logger.info("Create profile status code: {}".format(r.status_code))
	app.logger.debug(r.content)

	app.logger.info("/adduser user {} OK".format(data['username']))

	return { "status" : "OK" }, 200

# Verify
@app.route("/verify", methods=["POST"])
def verify_user():
	#print(80*'=')
	#print("/VERIFY() CALLED")
	data = request.json
	#print("DATA", data)
	app.logger.debug("/verify data: " + json.dumps(data))

	if "email" not in data or "key" not in data:
		return { "status" : "error", "error": "Email or key not specified in request" }, 200 #400

	email = data["email"]
	token = data["key"]

	cursor = db.cursor()
	try:
		#Check email is in database
		if check_email(email, cursor) == False:
			#print("error: DATABASE CHECK EMAIL FAILED")
			app.logger.info("/verify email not found in database <{}>".format(data['email']))
			return { "status" : "error", "error": "Email not found" }, 400

		app.logger.debug("/verify email check passed <{}>".format(data['email']))

		# skip check if backdoor used
		if token != "abracadabra":
			try:
				ret = confirm_token(token)
				#print("CONF_TOKEN:", ret)
				if email != ret:
					#print("WEE WOO WEE WOO BAD EMAIL")
					app.logger.info("/verify email {} key failed".format(data['email']))
					return { "status" : "error", "error" : "Bad email or key" }, 400
			except Exception as e:
				#print(e)
				app.logger.info("/verify email unknown error <{}>".format(data['email']))
				app.logger.debug(e)
				return { "status" : "error", "error": "Contact a developer" }, 400

		app.logger.debug("/verify email successful <{}>".format(data['email']))

		#print("VERIFY: ", str(email))
		sql = "UPDATE users SET validated = 1 WHERE email = %s"
		cursor.execute(sql, (email,))
		db.commit()
	finally:
		cursor.close()

	app.logger.info("/verify email OK <{}>".format(data['email']))

	return { "status" : "OK"}, 200

# Login
@app.route('/login', methods=["POST"])
def login():
	#print(80*'=')
	#print("/LOGIN() CALLED")
	creds = request.json
	#print("CREDS:", creds)
	app.logger.debug("/login creds: " + json.dumps(creds))

	db_user = None
	cursor = db.cursor()
	try:
		# Get user info
		db_user = get_user(creds['username'], cursor)

		# User does not exist
		if not db_user:
			#print("NO USER")
			app.logger.info("/login user {} not found".format(creds['username']))
			return { "status" : "error", "error" : "Username not found" }, 400

		# #print("USER VALID", str(user['validated']))
		app.logger.debug("/login user {} exists".format(creds['username']))

		if not db_user['validated']: 
			#print("NOT VALIDATED")
			app.logger.info("/login user {} not validated".format(creds['username']))
			return { "status" : "error", "error" : "User has not been validated" }, 400
	finally:
		cursor.close()

	app.logger.debug("/login user {} validated".format(creds['username']))
	
	if bcrypt.checkpw(creds['password'].encode('utf8'), db_user['password_hash'].encode('utf8')):
		#print("LOGIN GOOD")
		app.logger.debug("/login user {} good password".format(creds['username']))
	else:
		#print("INCORRECT PASSWORD")
		app.logger.info("/login user {} bad password".format(creds['username']))
		return { "status" : "error", "error" : "Incorrect password" }, 400

	app.logger.info("/login user {} OK".format(creds['username']))

	return { "status" : "OK", "username": creds['username'] }, 200

## Logout
#@app.route('/logout', methods=["POST"])
#def logout():
#	session.clear()
#	return { "status" : "OK"}, 200

if __name__ == "__main__":
	print("main")
	app.run()
