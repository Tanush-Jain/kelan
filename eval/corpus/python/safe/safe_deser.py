import json
import yaml


def safe_load_session(serialized_json):
    # Safe JSON deserialization
    return json.loads(serialized_json)


def safe_load_config(raw_yaml):
    # Safe YAML load with SafeLoader
    return yaml.load(raw_yaml, Loader=yaml.SafeLoader)

