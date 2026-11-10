import pickle
import yaml


def load_session(serialized_blob):
    # Insecure deserialization via pickle
    return pickle.loads(serialized_blob)


def load_config(raw_yaml):
    # Insecure deserialization via unsafe yaml load
    return yaml.load(raw_yaml)
