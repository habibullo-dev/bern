import datetime
import jwt
import logging
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from .forms import LoginForm, SignupForm, ClaimRewardForm
from .models import users_collection, sessions_collection, quests_collection, rewards_collection, user_quest_rewards_collection
from flask import current_app as app
from bson import ObjectId

auth = Blueprint('auth', __name__)

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('pymongo').setLevel(logging.WARNING)

def update_user_rewards(user_id, quest):
    logging.debug(f"Updating rewards for user {user_id} and quest {quest['name']}")
    reward = rewards_collection.find_one({"quest_id": quest["_id"]})
    if reward:
        user_id = ObjectId(user_id) if isinstance(user_id, str) else user_id
        if reward["item_type"] == "gold":
            users_collection.update_one({"_id": user_id}, {"$inc": {"gold": reward["quantity"]}})
        elif reward["item_type"] == "diamond":
            users_collection.update_one({"_id": user_id}, {"$inc": {"diamond": reward["quantity"]}})
        
        user_quest_rewards_collection.update_one(
            {
                "user_id": user_id,
                "quest_id": quest["_id"],
                "status": "not_claimed"
            },
            {
                "$set": {
                    "status": "claimed",
                    "progress": quest["streak"],
                    "times_completed": 1,
                    "updated_at": datetime.datetime.now(datetime.timezone.utc)
                }
            }
        )
        logging.debug(f"Rewards updated successfully for user {user_id}")

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = users_collection.find_one({"email": form.email.data})
        if user and check_password_hash(user['password'], form.password.data):
            session_id = sessions_collection.insert_one({
                "user_id": user['_id'],
                "created_at": datetime.datetime.now(datetime.timezone.utc),
                "expires_at": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            }).inserted_id
            
            quest = quests_collection.find_one({"name": "sign-in-three-times"})
            if quest:
                current_time = datetime.datetime.now(datetime.timezone.utc)
                logging.debug(f"Processing login quest for user {user['_id']}")

                # Find or create quest progress
                user_quest_reward = user_quest_rewards_collection.find_one({
                    "user_id": user["_id"],
                    "quest_id": quest["_id"],
                    "status": "not_claimed"
                })

                if not user_quest_reward:
                    # Check if we should start a new quest attempt
                    completed_count = user_quest_rewards_collection.count_documents({
                        "user_id": user["_id"],
                        "quest_id": quest["_id"],
                        "status": "claimed"
                    })
                    
                    if completed_count < quest["duplication"]:
                        user_quest_reward = {
                            "user_id": user["_id"],
                            "quest_id": quest["_id"],
                            "status": "not_claimed",
                            "progress": 0,  # Start at 0, will increment to 1
                            "times_completed": completed_count,
                            "created_at": current_time,
                            "updated_at": current_time
                        }
                        user_quest_rewards_collection.insert_one(user_quest_reward)

                if user_quest_reward:
                    updated_at = user_quest_reward.get("updated_at")
                    if updated_at and (updated_at.tzinfo is None):
                        updated_at = updated_at.replace(tzinfo=datetime.timezone.utc)
                    time_since_update = current_time - updated_at if updated_at else datetime.timedelta(hours=2)

                    if time_since_update > datetime.timedelta(minutes=1):  # Using 1 minute for testing
                        new_progress = user_quest_reward["progress"] + 1
                        logging.debug(f"Updating progress from {user_quest_reward['progress']} to {new_progress}")
                        
                        result = user_quest_rewards_collection.update_one(
                            {
                                "user_id": user["_id"],
                                "quest_id": quest["_id"],
                                "status": "not_claimed"
                            },
                            {
                                "$set": {
                                    "progress": new_progress,
                                    "updated_at": current_time
                                }
                            }
                        )
                        
                        if new_progress >= quest["streak"]:
                            update_user_rewards(user["_id"], quest)
                            logging.debug("Quest completed and rewards updated")

            token = jwt.encode({
                'user_id': str(user['_id']),
                'session_id': str(session_id),
                'exp': current_time + datetime.timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            session['user_id'] = str(user['_id'])
            session['token'] = token
            return redirect(url_for('main.index'))
            
        flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user_id = users_collection.insert_one({
            "email": form.email.data,
            "password": hashed_password,
            "status": "new",
            "gold": 0,
            "diamond": 0,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
        }).inserted_id

        # Handle first-signup quest
        quest = quests_collection.find_one({"name": "first-signup"})
        if quest and quest["auto_claim"]:
            # Give the reward
            update_user_rewards(user_id, quest)
            
            # Track quest completion in user_quest_rewards
            user_quest_rewards_collection.insert_one({
                "user_id": user_id,
                "quest_id": quest["_id"],
                "status": "claimed",
                "progress": quest["streak"],  # Will be 1 for signup quest
                "times_completed": 1,
                "created_at": datetime.datetime.now(datetime.timezone.utc),
                "updated_at": datetime.datetime.now(datetime.timezone.utc)
            })

        flash('Your account has been created!', 'success')
        return redirect(url_for('auth.login'))
    return render_template('signup.html', form=form)

@auth.route('/claim_reward', methods=['POST'])
def claim_reward():
    if not session.get('user_id'):
        flash('Please login first', 'error')
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    quest_id = request.form.get('quest_id')
    
    if not quest_id:
        flash('Missing quest information', 'error')
        return redirect(url_for('main.index'))
        
    try:
        quest = quests_collection.find_one({"_id": ObjectId(quest_id)})
        if not quest:
            flash('Quest not found', 'error')
            return redirect(url_for('main.index'))

        # Verify quest completion status
        user_quest_reward = user_quest_rewards_collection.find_one({
            "user_id": ObjectId(user_id),
            "quest_id": ObjectId(quest_id),
            "status": "not_claimed"
        })
        
        if not user_quest_reward:
            flash('No claimable reward found', 'error')
            return redirect(url_for('main.index'))

        if user_quest_reward["progress"] < quest["streak"]:
            flash('Quest requirements not met', 'error')
            return redirect(url_for('main.index'))

        completed_count = user_quest_rewards_collection.count_documents({
            "user_id": ObjectId(user_id),
            "quest_id": ObjectId(quest_id),
            "status": "claimed"
        })

        if completed_count >= quest["duplication"]:
            flash('Maximum quest completions reached', 'error')
            return redirect(url_for('main.index'))

        # Update reward status and user's currency
        reward = rewards_collection.find_one({"quest_id": quest["_id"]})
        if reward:
            currency_field = "gold" if reward["item_type"] == "gold" else "diamond"
            users_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$inc": {currency_field: reward["quantity"]}}
            )

            user_quest_rewards_collection.update_one(
                {"_id": user_quest_reward["_id"]},
                {
                    "$set": {
                        "status": "claimed",
                        "times_completed": completed_count + 1,
                        "updated_at": datetime.datetime.now(datetime.timezone.utc)
                    }
                }
            )
            flash('Reward claimed successfully!', 'success')
            
        return redirect(url_for('main.index'))
        
    except Exception as e:
        logging.error(f"Error claiming reward: {str(e)}")
        flash('Error processing reward claim', 'error')
        return redirect(url_for('main.index'))

@auth.route('/validate_token', methods=['POST'])
def validate_token():
    token = request.json.get('token')
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']
        session_id = data['session_id']
        session = sessions_collection.find_one({"_id": ObjectId(session_id), "user_id": ObjectId(user_id)})
        if session and session['expires_at'] > datetime.datetime.now(datetime.timezone.utc):
            user = users_collection.find_one({"_id": ObjectId(user_id)})
            if user:
                return jsonify({'message': 'Token is valid', 'user': user['email']})
            else:
                return jsonify({'message': 'Invalid token'}), 401
        else:
            return jsonify({'message': 'Session expired or invalid'}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401