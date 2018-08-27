'''
ampt-generator Flask app and REST API

'''
import pkg_resources

from flask import Flask


__version__ = pkg_resources.get_distribution('ampt_generator').version
__url__ = 'https://github.com/nids-io/ampt-generator'

app = Flask(__name__)
app.config.from_object('ampt_generator.settings')

from . import api

