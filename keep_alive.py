from flask import Flask
from threading import Thread
import logging

# Disable Flask logs to keep console clean
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask('')

@app.route('/')
def home():
    return "🚀 Bot System is Active and Running!"

def run():
    try:
        app.run(host='0.0.0.0', port=8080)
    except Exception as e:
        print(f"❌ Keep-Alive Server Error: {e}")

def keep_alive():
    t = Thread(target=run)
    t.start()
