from app.home import app, socketio
if __name__ == "__main__":
	socketio.run(app, host = '0.0.0.0', port = 5001)
	app.run()
