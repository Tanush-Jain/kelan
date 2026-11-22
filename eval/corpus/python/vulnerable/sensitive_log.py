import logging


def process_login(username, password):
    # Sensitive password variable directly exposed to logging sink
    logging.info(f"User login attempt: user={username} password={password}")
