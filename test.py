import google.generativeai as genai
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini AI API
my_api_key_gemini = os.getenv("GEMINI_API_KEY")
if not my_api_key_gemini:
    raise ValueError("GEMINI_API_KEY environment variable is not set.")
genai.configure(api_key=my_api_key_gemini)

# Initialize the model - FIXED MODEL NAME
try:
    model = genai.GenerativeModel("gemini-1.5-pro-latest")  # Changed from gemini-pro
    print("Gemini model initialized successfully.")
except Exception as model_error:
    print(f"Model Initialization Error: {model_error}")
    raise RuntimeError("Failed to initialize Gemini AI model.")

# Test the API with a simple health-related question
try:
    response = model.generate_content("What is telemedicine?")
    print("Response from Gemini API:")
    print(response.text)
except Exception as e:
    print(f"Gemini API Error: {e}")