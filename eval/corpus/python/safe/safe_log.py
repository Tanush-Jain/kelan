import logging


def safe_process_login(username, password):
    logging.info(f"User login attempt: user={username}")
