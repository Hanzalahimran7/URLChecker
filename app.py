from email import message
from flask import Flask, render_template, request
import os
import pickle
# Gmail API utils
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
# for encoding/decoding messages in base64
from base64 import urlsafe_b64decode, urlsafe_b64encode
# for dealing with attachement MIME types
from email.mime.text import MIMEText
from mimetypes import guess_type as guess_mime_type
import requests
import socket

# Request all access (permission to read/send/receive emails, manage the inbox, and more)
SCOPES = ['https://mail.google.com/']
our_email = 'i170107@nu.edu.pk'
app = Flask(__name__)



def gmail_authenticate():
    creds = None
    # the file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
    # if there are no (valid) credentials availablle, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('client_secret.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # save the credentials for the next run
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)

# get the Gmail API service
service = gmail_authenticate()

def build_message(destination, obj, body):
    message = MIMEText(body)
    message['to'] = destination
    message['from'] = our_email
    message['subject'] = obj
    return {'raw': urlsafe_b64encode(message.as_bytes()).decode()}

def send_message(service, destination, obj, body):
    return service.users().messages().send(
      userId="me",
      body=build_message(destination, obj, body)
    ).execute()

def getSecurityHeaders(domain,messageBody):
    response = requests.get(domain)
    messageBody+='\nSecurity Headers:\n'
    headers=['Cross-Origin-Resource-Policy','Content-Security-Policy','Content-Security-Policy-Report-Only','Expect-CT','Feature-Policy','Public-Key-Pins','Public-Key-Pins-Report-Only','Strict-Transport-Security','Upgrade-Insecure-Requests','X-Content-Type-Options','X-Frame-Options','X-XSS-Protection']
    for i in response.headers:
        if i in headers:
            messageBody=messageBody+'\t'+i+" : "+response.headers[i]+'\n'
        else:
            messageBody=messageBody+'\t'+i+" : N/A"+'\n'
    return messageBody

def getCookieInformation(domain,messageBody):
    messageBody=messageBody+'\n\nThe Cookie details:\n'
    r = requests.get(domain)
    for i in r.cookies.items():
        messageBody=messageBody+i[0]+'\t:\t'+i[1]+'\n\n'
    messageBody=messageBody+'\n\n\nThe Cookies are as follow:\n'
    for c in r.cookies:
        messageBody=messageBody+'\t'+c.name +'==>>'+ c.value+'==>>'+ c.domain+'\n'
        if c.domain[1:] not in domain:
            messageBody=messageBody+'\t\tThird party Cookie\n'
        elif c.expires!=None:
            messageBody=messageBody+'\t\tPersistent Cookie\n'
        else:
            messageBody=messageBody+'\t\tSession Cookie\n'
        messageBody+='\n'
    messageBody+='\n'
    return messageBody

def getPortNumbers(domain,messageBody):
    print(domain)
    domain=domain[:domain.find('/')]
    print(domain)
    messageBody=messageBody+'The Port numbers are as follow:\n'
    remoteServerIP  = socket.gethostbyname(domain)
    for port in [80,443]:  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            messageBody=messageBody+"Port {}: 	 Open\n".format(port)
        else:
            messageBody=messageBody+"Port {}: 	 Close\n".format(port)
        sock.close()
    return messageBody


#send_message(service, "i170556@nu.edu.pk", "This is a subject", "This is the body of the email")


@app.route('/')
def main():
    return render_template('app.html')


@app.route('/send', methods=['POST'])
def send(sum=sum):
    messageBody='The requested information is \n'
    if request.method == 'POST':
        num1 = request.form['num1']
        domain=num1
        if 'https://' not in domain:
            domain='https://'+domain
        messageBody=getSecurityHeaders(domain,messageBody)+'\n\n'
        messageBody=getCookieInformation(domain,messageBody)+'\n\n'
        if domain[-1]=='/':
            domain=domain[:len(domain)-1]
        if 'https://www.' in domain:
            print(domain[12:])
            messageBody=getPortNumbers(domain[12:],messageBody)
        elif 'https://' in domain:
            messageBody=getPortNumbers(domain[8:],messageBody)
        elif 'http://www.' in domain:
            messageBody=getPortNumbers(domain[11:],messageBody)
        elif 'http://' in domain:
            messageBody=getPortNumbers(domain[7:],messageBody)
        else:
            getPortNumbers(domain,messageBody)
    send_message(service, "hanzalahimran9@gmail.com", "URL Information", messageBody)

    return render_template('app.html', sum=messageBody)

if __name__ == ' __main__':
    app.debug = True
    app.run()
