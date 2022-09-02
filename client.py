import requests
import random
import numpy as np
import threading
import concurrent.futures
import time
import traceback
import json

def login(username, password, timeout=None):
    data = {'username': username, 'password': password}
    response = requests.post('http://localhost:8000/users/login', data=data, timeout=timeout)
    return response

def logout(timeout=None):
    response = requests.get('http://localhost:8000/users/logout', timeout=timeout)
    return response

def register(username, password1, password2, timeout=None):
    data = {'username': username, 'password1': password1, 'password2': password2}
    response = requests.post('http://localhost:8000/users/register', data=data, timeout=timeout)
    return response

def send_long_url(long_url, timeout=None):
    data = {'long_url': long_url}
    response = requests.post('http://localhost:8000/create', data=data, timeout=timeout)
    return response

def send_short_url(short_url, timeout=None):
    response = requests.get(short_url, timeout=timeout)
    return response

def get_my_urls(timeout=None):
    response = requests.get('http://localhost:8000/users/get-my-urls', timeout=timeout)
    return response

def get_whoami(timeout=None):
    response = requests.get('http://localhost:8000/users/whoami', timeout=timeout)
    return response

def get_status(stop_event, running_time):
    start_time = time.time()
    time.sleep(running_time)
    stop_event.set()
    total_reqs = 0
    total_success = 0
    for c in clients:
        total_reqs += c.total_reqs
        total_success += c.successful_reqs
    stop_time = time.time()
    print(f'total requests: {total_reqs}, successful requests: {total_success}')
    print(f'success rate: {np.round(total_success/total_reqs, 3) * 100} %, time elapsed: {stop_time - start_time}')


class Client:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.total_reqs = 0
        self.successful_reqs = 0

    def attack(self, stop_event, total_time):

        waiting_time = np.random.rand() * total_time * 0.5
        time.sleep(waiting_time)
        self.total_reqs += 3
        
        response = register(self.username, self.password, self.password)
        if response:
            self.successful_reqs += 1
        response = login(self.username, self.password)
        if response:
            self.successful_reqs += 1
        response = get_whoami()
        if response:
            self.successful_reqs += 1

        while not stop_event.is_set():
            try:
                self.total_reqs += 2
                response = send_long_url('https://stackoverflow.com/')
                short_url = json.loads(response.text)['short url']
                if response:
                    self.successful_reqs += 1
                response = send_short_url(short_url)
                if response:
                    self.successful_reqs += 1
            except:
                print(response.text)
                traceback.print_exc()


if __name__ == '__main__':
    characters = [chr(i) for i in range(65, 123) if i not in range(91, 97)]
    digits = [str(i) for i in range(1, 10)]
    characters.extend(digits)
    
    num_clients = 100
    running_time = 60
    clients = []

    stop_event = threading.Event()

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_clients) as executer: 
        executer.submit(get_status, stop_event, running_time)
        for i in range(num_clients):
            print(i)
            rand_username = ''.join(random.choices(characters, k=10))
            rand_password = ''.join(random.choices(characters, k=10))
            c = Client(rand_username, rand_password)
            clients.append(c)
            executer.submit(c.attack, stop_event, running_time)

