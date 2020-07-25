from functools import wraps
import json
from os import environ as env
from dotenv import load_dotenv, find_dotenv
from imutils.video import VideoStream
from flask_socketio import SocketIO
from flask import Flask , Response , request, render_template, jsonify, redirect, session, url_for
import threading
import datetime
import imutils
import time
import cv2
import os
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from werkzeug.exceptions import HTTPException



import constants

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)


outputFrame = None
lock = threading.Lock()

app = Flask(__name__, static_folder = 'uploads')
socketio = SocketIO(app)

app.secret_key = constants.SECRET_KEY

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            return redirect('/')
        return f(*args, **kwargs)

    return decorated




@app.route('/home')
def home():
    return render_template('main.html',
                       userinfo=session['profile'])

@app.route('/stream')
@requires_auth
def stream():
    #auth0.authorize_access_token()

    return render_template('stream.html', userinfo=session['profile'])

def generate():
	# loop over frames from the output stream
	vs = cv2.VideoCapture("rtsp://admin:emma2014@174.48.62.199:554/cam/realmonitor?channel=1&subtype=0")
	while True:
		success, frame = vs.read()
		if not success:
			break
		else:
			frame = imutils.resize(frame, width=400)
			gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
			gray = cv2.GaussianBlur(gray, (7, 7), 0)
		# grab the current timestamp and draw it on the frame
			timestamp = datetime.datetime.now()
			cv2.putText(frame, timestamp.strftime(
				"%A %d %B %Y %I:%M:%S%p"), (10, frame.shape[0] - 10),
				cv2.FONT_HERSHEY_SIMPLEX, 0.35, (0, 0, 255), 1)
			(flag, encodedImage) = cv2.imencode(".jpg", frame)
			frame = encodedImage.tobytes()

		# yield the output frame in the byte format
			yield(b'--frame\r\n' b'Content-Type: image/jpeg\r\n\r\n' +
				frame + b'\r\n')
	vs.release()
@app.route('/video_feed')
@requires_auth
def video_feed():
	# return the response generated along with the specific media
	# type (mime type)
	return Response(generate(),
		mimetype = "multipart/x-mixed-replace; boundary=frame")

@app.route('/callback')
def callback_handling():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/home')

@socketio.on('connect', namespace = '/web')
def connect_web():
	print('[INFO] Web client connected: {}'.format(request.sid))

@socketio.on('disconnect', namespace = '/web')
def disconnect_web():
	print('[INFO] Web client disconnected: {}'.format(request.sid))

@socketio.on('connect', namespace = '/cv')
def connect_cv():
	print('[INFO] CV client connected: {}'.format(request.sid))

@socketio.on('disconnect', namespace = '/cv')
def disconnect_cv():
	print('[INFO] CV client disconnected: {}'.format(request.sid))

@socketio.on('cv2server')
def handle_cv_message(message):
	socketio.emit('server2web', message, namespace='/web')


@app.route('/')
def login():
    return auth0.authorize_redirect(redirect_uri='https://mighty-beach-20841.herokuapp.com/callback')


app.config["VIDEO_UPLOADS"] = "C:\\Users\\Amed\\Desktop\\CNT4713\\uploads"
@app.route('/static_video', methods = ["GET", "POST"])
#@requires_auth
def static_video():
    if request.method == "POST":
        if request.files:
            video_upload = request.files["video_upload"]
            video_upload.save(os.path.join(app.config["VIDEO_UPLOADS"],video_upload.filename))
            return redirect(request.url)
    return render_template('static_video.html', userinfo = session['profile'])


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session['jwt_payload'], indent=4))


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('login', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))
