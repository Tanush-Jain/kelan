from fastapi import Depends, FastAPI

app = FastAPI()


def get_current_admin():
    return "admin"


@app.delete("/admin/users/{user_id}")
def safe_delete_user(user_id: int, admin: str = Depends(get_current_admin)):
    return {"status": "deleted", "id": user_id}
