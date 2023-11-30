#!/usr/bin/env python3

from flask import Flask, jsonify, request
import redis
from redis.commands.json.path import Path
import secrets
import os

# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
)

app = Flask(__name__)


@app.route("/nefcallbacks", methods=["POST"])
def nefcallback():
    if not r.exists('nef_callback_counter'):
        callback_counter = 0
        r.set('nef_callback_counter', callback_counter)
    callback_counter = int(r.get('nef_callback_counter'))

    r.set('nef_callback:'+str(callback_counter), str(request.json))
    callback_counter += 1
    r.set('nef_callback_counter', str(callback_counter))

    result = r.get('nef_callback:' + str(callback_counter-1))
    print(result)

    return jsonify(message=result), 201


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
