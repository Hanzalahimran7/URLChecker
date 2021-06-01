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

def getSecurityHeaders(domain):
    response = requests.get(domain)
    print(domain)
    headers=['Cross-Origin-Resource-Policy','Content-Security-Policy','Content-Security-Policy-Report-Only','Expect-CT','Feature-Policy','Public-Key-Pins','Public-Key-Pins-Report-Only','Strict-Transport-Security','Upgrade-Insecure-Requests','X-Content-Type-Options','X-Frame-Options','X-XSS-Protection']
    for i in response.headers:
        if i in headers:
            print(i+" : "+response.headers[i])
        else:
            print(i+" : N/A")

def getCookieInformation(domain):
    r = requests.get(+domain)
    for c in r.cookies:
        print(c.name +"==>>", c.value+"==>>", c.domain)
        if c.domain[1:] not in domain:
            print("Third party Cookie")
        elif c.expires!=None:
            print("Persistent Cookie")
        else:
            print("Session Cookie")
        print()

def getPortNumbers(domain):
    remoteServerIP  = socket.gethostbyname(domain)
    for port in range(1,1025):  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            print ("Port {}: 	 Open".format(port))
        else:
            print ("Port {}: 	 Close".format(port))
        sock.close()


send_message(service, "i170556@nu.edu.pk", "This is a subject", 
            "This is the body of the email")