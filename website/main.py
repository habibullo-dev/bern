from flask import Blueprint, render_template, session
from .models import users_collection, user_quest_rewards_collection, quests_collection
from .forms import ClaimRewardForm
from bson import ObjectId

main = Blueprint('main', __name__)

@main.route('/')
def index():
    user_id = session.get('user_id')
    if user_id:
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        
        # Get unique quest statuses
        rewards_info = []
        available_quests = []
        for quest in quests_collection.find():
            # Get the latest reward status for this quest
            latest_reward = user_quest_rewards_collection.find_one({
                "user_id": ObjectId(user_id),
                "quest_id": quest["_id"]
            }, sort=[("updated_at", -1)])  # Get the most recent one
            
            if latest_reward:
                rewards_info.append({
                    "quest_name": quest["name"],
                    "status": latest_reward["status"],
                    "progress": latest_reward["progress"],
                    "streak": quest["streak"],
                    "quest_id": str(quest["_id"]),
                    "times_completed": latest_reward["times_completed"]
                })
                if latest_reward["status"] == "not_claimed":
                    available_quests.append(quest)
            else:
                available_quests.append(quest)

        form = ClaimRewardForm()
        return render_template('index.html', 
                             user=user, 
                             rewards_info=rewards_info, 
                             available_quests=available_quests, 
                             form=form)
    return render_template('index.html')