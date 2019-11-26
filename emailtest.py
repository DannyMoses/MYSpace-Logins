import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

message = Mail(
	from_email='ubuntu@myspace-logins-1.c.winged-sol-258623.internal',
	to_emails='daniel.moses@stonybrook.edu',
	subject='SENDGRID API TEST',
	html_content="validation key: &lt;" + "fdsheywreyw" + "&gt;")

try:
	sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
	response = sg.send(message)
	print(response.status_code)
	print(response.body)
	print(response.headers)
except Exception as e:
	print(str(e))
