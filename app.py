from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_pymongo import PyMongo
import google.generativeai as genai
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId
import logging
from functools import wraps

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/chatbot"
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=1)
app.config["SESSION_TYPE"] = "filesystem"
# CORS(app)  
# # Allow frontend to access backend
# Remove the complex CORS config and replace with:
CORS(app, supports_credentials=True, origins=["http://localhost:5000", "http://127.0.0.1:5000"])
bcrypt = Bcrypt(app)
mongo = PyMongo(app)

users_collection = mongo.db.users
chats_collection = mongo.db.chats

# Configure Gemini AI API
my_api_key_gemini = os.getenv("GEMINI_API_KEY")
if not my_api_key_gemini:
    raise ValueError("GEMINI_API_KEY environment variable is not set.")
genai.configure(api_key=my_api_key_gemini)

try:
    model = genai.GenerativeModel("gemini-1.5-pro-latest")
    logger.info("Gemini model initialized successfully.")
except Exception as model_error:
    logger.error(f"Model Initialization Error: {model_error}")
    raise RuntimeError("Failed to initialize Gemini AI model.")
@app.after_request
def after_request(response):
    # Add necessary headers for CORS and session
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5000')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response
# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized access"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("chat"))
    return render_template('login.html')

@app.route("/chat")
def chat():
    if "user_id" not in session:
        return redirect(url_for("home"))
    return render_template("index.html", email=session["email"])

# User Registration
@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        first_name = data.get("firstName")
        last_name = data.get("lastName")
        email = data.get("email")
        password = data.get("password")
        confirm_password = data.get("confirmPassword")

        # Validation
        if not all([first_name, last_name, email, password, confirm_password]):
            return jsonify({"error": "All fields are required"}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords don't match"}), 400

        if users_collection.find_one({"email": email}):
            return jsonify({"error": "Email already exists"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        user_data = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": hashed_password,
            "created_at": datetime.utcnow()
        }
        
        user_id = users_collection.insert_one(user_data).inserted_id
        
        # Automatically log in the user after signup
        session["user_id"] = str(user_id)
        session["email"] = email
        session["first_name"] = first_name
        session["last_name"] = last_name
        
        return jsonify({
            "message": "Signup successful",
            "redirect": "/chat"
        }), 201

    except Exception as e:
        logger.error(f"Signup error: {e}")
        return jsonify({"error": "An error occurred during signup"}), 500

# User Login
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")
        remember_me = data.get("rememberMe", False)

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        user = users_collection.find_one({"email": email})
        if not user or not bcrypt.check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid email or password"}), 401

        # Set session data
        session["user_id"] = str(user["_id"])
        session["email"] = user["email"]
        session["first_name"] = user.get("first_name", "")
        session["last_name"] = user.get("last_name", "")

        # Set session permanence based on remember me
        session.permanent = remember_me

        return jsonify({
            "message": "Login successful", 
            "redirect": "/chat",
            "user": {
                "email": user["email"],
                "firstName": user.get("first_name", ""),
                "lastName": user.get("last_name", "")
            }
        }), 200

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": "An error occurred during login"}), 500

# User Logout
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    try:
        session.clear()
        return jsonify({"message": "Logged out successfully", "redirect": "/"}), 200
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({"error": "An error occurred during logout"}), 500

# Solar system keywords for topic restriction
HEALTH_SYSTEM_KEYWORDS = [
    "wearable health tech", "remote patient monitoring", "telemedicine", "AI diagnostics", 
    "predictive analytics in healthcare", "digital biomarkers", "electronic health records (EHR) interoperability", 
    "robotic surgery", "virtual nursing assistants", "healthcare chatbots", "genomic sequencing", 
    "precision oncology", "liquid biopsies", "microbiome therapeutics", "digital health passports", 
    "automated mental health screening", "AI radiology", "digital phenotyping", "personal health ecosystems", 
    "AI-assisted clinical trials"
]

def is_health_system_related(prompt):
    prompt_lower = prompt.lower()
    return any(keyword in prompt_lower for keyword in HEALTH_SYSTEM_KEYWORDS)

# Chat endpoint
@app.route("/ask", methods=["POST"])
@login_required
def ask():
    try:
        prompt_text = request.json.get("question")
        if not prompt_text:
            return jsonify({"error": "No prompt provided"}), 400

        if not is_health_system_related(prompt_text):
            return jsonify({
                "error": "I'm programmed to answer onlY Technology -related topics."
            }), 400

        # Generate response using Gemini API
        response = model.generate_content(prompt_text)
        answer = response.text.strip() if response.text else "I'm sorry, I couldn't generate a response."

        # Save the chat to MongoDB
        chat_data = {
            "user_id": session["user_id"],
            "question": prompt_text,
            "answer": answer,
            "likes": 0,
            "dislikes": 0,
            "timestamp": datetime.utcnow(),
            "ratings": []
        }
        
        chat_id = chats_collection.insert_one(chat_data).inserted_id
        
        return jsonify({
            "data": answer,
            "chat_id": str(chat_id)
        }), 200

    except Exception as e:
        logger.error(f"Ask error: {e}")
        return jsonify({"error": "Failed to process your request"}), 500

# Chat history operations
@app.route("/get_chat_history", methods=["GET"])
@login_required
def get_chat_history():
    try:
        chats = list(chats_collection.find(
            {"user_id": session["user_id"]},
            {"_id": 1, "question": 1, "timestamp": 1}
        ).sort("timestamp", -1).limit(50))
        
        # Convert ObjectId and datetime to strings
        for chat in chats:
            chat["_id"] = str(chat["_id"])
            chat["timestamp"] = chat["timestamp"].isoformat()
        
        return jsonify({"chat_history": chats}), 200
    except Exception as e:
        logger.error(f"Chat history error: {e}")
        return jsonify({"error": "Failed to fetch chat history"}), 500

@app.route("/delete_chat/<chat_id>", methods=["DELETE"])
@login_required
def delete_chat(chat_id):
    try:
        result = chats_collection.delete_one({
            "_id": ObjectId(chat_id),
            "user_id": session["user_id"]
        })
        
        if result.deleted_count == 0:
            return jsonify({"error": "Chat not found or not authorized"}), 404
            
        return jsonify({"message": "Chat deleted successfully"}), 200
    except Exception as e:
        logger.error(f"Delete chat error: {e}")
        return jsonify({"error": "Failed to delete chat"}), 500

@app.route("/delete_chat_history", methods=["DELETE"])
@login_required
def delete_chat_history():
    try:
        chats_collection.delete_many({"user_id": session["user_id"]})
        return jsonify({"message": "Chat history cleared successfully"}), 200
    except Exception as e:
        logger.error(f"Clear history error: {e}")
        return jsonify({"error": "Failed to clear chat history"}), 500

# Rating system
@app.route("/rate_chat/<chat_id>", methods=["POST"])
@login_required
def rate_chat(chat_id):
    try:
        data = request.json
        action = data.get("action")  # "like" or "dislike"

        if action not in ["like", "dislike"]:
            return jsonify({"error": "Invalid action"}), 400

        # Check if user already rated this chat
        existing_rating = chats_collection.find_one({
            "_id": ObjectId(chat_id),
            "ratings.user_id": session["user_id"]
        })

        if existing_rating:
            return jsonify({"error": "You've already rated this chat"}), 400

        # Update rating
        update_field = "likes" if action == "like" else "dislikes"
        chats_collection.update_one(
            {"_id": ObjectId(chat_id)},
            {
                "$inc": {update_field: 1},
                "$push": {
                    "ratings": {
                        "user_id": session["user_id"],
                        "action": action,
                        "timestamp": datetime.utcnow()
                    }
                }
            }
        )
        
        return jsonify({"message": f"Chat {action}d successfully"}), 200
    except Exception as e:
        logger.error(f"Rating error: {e}")
        return jsonify({"error": "Failed to process rating"}), 500

# User profile
@app.route("/profile", methods=["GET"])
@login_required
def get_profile():
    try:
        user = users_collection.find_one(
            {"_id": ObjectId(session["user_id"])},
            {"password": 0}  # Exclude password
        )
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        user["_id"] = str(user["_id"])
        return jsonify({"user": user}), 200
    except Exception as e:
        logger.error(f"Profile error: {e}")
        return jsonify({"error": "Failed to fetch profile"}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)