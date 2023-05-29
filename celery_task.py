from flask import Flask, request, jsonify
from celery import Celery
import redis
import json

app = Flask(__name__)
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

redis_client = redis.Redis()


@celery.task
def create_task(data):
    object_id = redis_client.incr('object_id_counter')
    redis_client.hset('objects', object_id, data)
    task_info = {'status': 'pending', 'result': None}
    redis_client.hset('tasks', object_id, json.dumps(task_info))
    return object_id


@celery.task
def read_task(object_id):
    data = redis_client.hget('objects', object_id)
    return data


@celery.task
def update_task(object_id, updated_data):
    redis_client.hset('objects', object_id, updated_data)
    return object_id


@celery.task
def delete_task(object_id):
    redis_client.hdel('objects', object_id)
    return object_id


@app.route('/create', methods=['POST'])
def create():
    data = request.json
    task = create_task.delay(data)
    task_id = task.id
    task_info = {'status': 'pending', 'result': None}
    redis_client.hset('tasks', task_id, json.dumps(task_info))
    return jsonify({'task_id': task_id}), 202


@app.route('/read/<object_id>', methods=['GET'])
def read(object_id):
    task = read_task.delay(object_id)
    task_id = task.id
    task_info = {'status': 'pending', 'result': None}
    redis_client.hset('tasks', task_id, json.dumps(task_info))
    return jsonify({'task_id': task_id}), 202


@app.route('/update/<object_id>', methods=['PUT'])
def update(object_id):
    updated_data = request.json
    task = update_task.delay(object_id, updated_data)
    task_id = task.id
    task_info = {'status': 'pending', 'result': None}
    redis_client.hset('tasks', task_id, json.dumps(task_info))
    return jsonify({'task_id': task_id}), 202


@app.route('/delete/<object_id>', methods=['DELETE'])
def delete(object_id):
    task = delete_task.delay(object_id)
    task_id = task.id
    task_info = {'status': 'pending', 'result': None}
    redis_client.hset('tasks', task_id, json.dumps(task_info))
    return jsonify({'task_id': task_id}), 202


@app.route('/status/<task_id>', methods=['GET'])
def get_task_status(task_id):
    task_info = redis_client.hget('tasks', task_id)
    if task_info is None:
        return jsonify({'status': 'Task not found'}), 404
    task_info = json.loads(task_info.decode('utf-8'))
    return jsonify(task_info), 200


if __name__ == '__main__':
    app.run(debug=True)