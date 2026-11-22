from fastapi import FastAPI

app = FastAPI()


@app.delete("/admin/users/{user_id}")
def delete_user_account(user_id: int):
    # Missing auth check on sensitive admin endpoint
    return {"status": "deleted", "id": user_id}
