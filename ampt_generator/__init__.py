'''
ampt-generator Flask app and REST API

'''

from flask import Flask


__version__ = '0.2.4'
__url__ = 'https://github.com/nids-io/ampt-generator'

app = Flask(__name__)
app.config.from_object('ampt_generator.settings')

from . import api

