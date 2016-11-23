'''
ampt-generator Flask app and REST API
'''

import os
from flask import Flask

app = Flask(__name__)
app.config.from_object('ampt_generator.settings')
app.config.from_envvar('AMPT_GEN_SETTINGS', silent=True)

from . import api

