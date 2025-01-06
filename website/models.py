from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

MONGODB_USERNAME = os.getenv('MONGODB_USERNAME')
MONGODB_PWD = os.getenv('MONGODB_PWD')

uri = f"mongodb+srv://{MONGODB_USERNAME}:{MONGODB_PWD}@blogs.2turw.mongodb.net/?retryWrites=true&w=majority&appName=Blogs"

client = MongoClient(uri)
db = client['bern']

users_collection = db['users']
sessions_collection = db['sessions']
quests_collection = db['quests']
rewards_collection = db['rewards']
user_quest_rewards_collection = db['user_quest_rewards']