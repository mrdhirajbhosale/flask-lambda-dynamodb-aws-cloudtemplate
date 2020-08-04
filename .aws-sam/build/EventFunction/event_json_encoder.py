import decimal
import json
class EventJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return int(obj)
        return super(EventJSONEncoder, self).default(obj)