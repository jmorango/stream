from app.home import app
if __name__ == "__main__":
	socketio.run(app = home, host = '0.0.0.0', port = 5001)
    app.run()
