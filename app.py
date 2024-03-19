import os
import random
from functools import wraps

import flask
import numpy as np
import pandas as pd
from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
import requests
from dotenv import load_dotenv
import plotly.express as px
load_dotenv('.config')
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

google_client_id = os.getenv('GOOGLE_CLIENT_ID')
google_client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
google_redirect_uri = '/auth/redirect'

oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key=google_client_id,
    consumer_secret=google_client_secret,
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)
user_cache = {}
google_userinfo_url = requests.get('https://accounts.google.com/.well-known/openid-configuration').json()[
    'userinfo_endpoint']


def get_user(token=None):
    if token is None:
        token = session.get('google_token')[0]
    if token in user_cache:
        return user_cache[token]
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(google_userinfo_url, headers=headers)
    if response.status_code != 200:
        return False
    user_cache[token] = response.json()['email']
    return user_cache[token]


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'google_token' not in session or get_user() is False:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/auth/login')
def login():
    print(url_for('auth_redirect', _external=True))
    return google.authorize(callback=url_for('auth_redirect', _external=True))


@app.route('/auth/redirect')
def auth_redirect():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Login failed.'

    session['google_token'] = (response['access_token'], '')
    me = session.get('google_token')

    return redirect(request.args.get('next') or url_for('index'))


@app.route('/auth/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))


@app.route('/grid')
@login_required
def grid():
    random_nums = [format(i, "02d") for i in range(100)]
    random.shuffle(random_nums)

    return flask.render_template('grid.html', grid=[random_nums[i:i + 10] for i in range(0, 100, 10)])


@app.route('/')
def index():  # put application's code here
    return flask.render_template('index.html')

if not os.path.exists('times.csv'):
    with open('times.csv', 'w') as f:
        f.write('')
times_df = pd.read_csv('times.csv', header=None, names=['user', 'start_time', 'end_time'])
times_df['start_time'] = pd.to_datetime(times_df['start_time'], unit='s')
times_df['end_time'] = pd.to_datetime(times_df['end_time'], unit='s')

@app.post('/submit')
@login_required
def submit_time():
    user = get_user()
    start_time = int(request.form['start_time']) / 1000
    end_time = int(request.form['end_time']) / 1000
    with open('times.csv', 'a') as f:
        f.write(f'{user},{start_time},{end_time}\n')
    times_df.loc[len(times_df)] = {'user': user, 'start_time': pd.to_datetime(start_time, unit='s'), 'end_time': pd.to_datetime(end_time, unit='s')}

    return redirect(url_for('grid'))

@app.route('/leaderboard')
def leaderboard():
    leaderboard = times_df
    leaderboard['time'] = (leaderboard['end_time'] - leaderboard['start_time'])
    leaderboard = leaderboard.sort_values("time").groupby('user').first().reset_index()
    leaderboard['time'] = leaderboard['time'].astype(np.int64) / int(1e6)
    leaderboard = leaderboard.sort_values('time', ascending=False).reset_index(drop=True)
    leaderboard['time'] = leaderboard['time'].apply(lambda x: f'{int(x // 60000)}:{int((x//1000) % 60):02d}.{int(x % 1000):03d}')
    leaderboard['end_time'] = leaderboard['end_time'].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S'))
    leaderboard['user'] = leaderboard['user'].apply(lambda x: x[:5] + '***' + x[-1:] if len(x) > 6 else x[:-2] + '***')
    leaderboard = leaderboard.to_dict(orient='index')
    leaderboard = [leaderboard[i] for i in range(len(leaderboard))]
    return flask.render_template('leaderboard.html', leaderboard=leaderboard)

@app.route('/history')
@login_required
def history():
    user = get_user()
    user_history = times_df[times_df['user'] == user]
    user_history['time'] = (user_history['end_time'] - user_history['start_time']) / np.timedelta64(1, 's')

    fig = px.scatter(user_history, x='start_time', y='time', title='Your history')
    fig.update_xaxes(title_text='Start time')
    fig.update_yaxes(title_text='Time')
    fig.update_traces(marker=dict(size=12,
                                    line=dict(width=2,
                                                color='DarkSlateGrey')),
                        selector=dict(mode='markers'))

    return fig.to_html(include_plotlyjs='cdn')
if __name__ == '__main__':
    app.run()
