from typing import Dict, List

# This file acts as a simulated, in-memory database.
# In a real-world application, you would replace this with a
# persistent database like PostgreSQL, MySQL, or MongoDB.

# A dictionary to store user information.
# The keys are user emails (strings), and the values are dictionaries
# containing user data, like the hashed password.
user_db: Dict[str, dict] = {}

# A list to store task information.
# Each item in the list is a dictionary representing a single task.
task_db: List[Dict] = []