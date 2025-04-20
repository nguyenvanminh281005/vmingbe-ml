# import json

# test_users = {"admin": {"email": "admin@example.com", "password": "hashed_password"}}

# with open("users.json", "w") as f:
#     json.dump(test_users, f, indent=4)

# print("File users.json đã được cập nhật!")

from flask import Flask

app = Flask(__name__)

print(app.url_map)

# fetch("http://127.0.0.1:5000/auth/debug-users")
#   .then(response => {
#     console.log('Response status:', response.status);
#     return response.json();
#   })
#   .then(data => {
#     console.log("📜 Loaded users:", data);
#   })
#   .catch(error => {
#     console.error("❌ Error loading users:", error);
#   });
