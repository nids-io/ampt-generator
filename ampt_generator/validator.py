'''Dispatch request validation'''

import hmac
import json

from . import app


class HMACValidationError(Exception):
    'Failure validating HMAC in request'
    pass

class CounterValidationError(Exception):
    'Failure validating timestamp counter in request'
    pass

def validate_request(args):
    'Validate HMAC and timestamp counter on request'

    req_digest = args.pop('h')
    ts = args['ts']

    # XXX patch in config keys
    app.config['HMAC_KEY'] = 'ballz'
    app.config['HMAC_DIGEST'] = 'sha256'
    j = json.dumps(args, sort_keys=True)
    computed_digest = (hmac.new(bytes(app.config['HMAC_KEY'].encode('utf-8')),
                               j.encode('utf-8'), app.config['HMAC_DIGEST'])
                               .hexdigest())

    if not hmac.compare_digest(req_digest, computed_digest):
        raise HMACValidationError

    # XXX here the stored timestamp must be compared
    if not ts:
        raise CounterValidationError

