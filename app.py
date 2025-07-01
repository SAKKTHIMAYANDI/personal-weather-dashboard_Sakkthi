from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session,render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
import requests
import os
from datetime import datetime, timedelta
import re

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///weather_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

WEATHER_API_KEY = '0c5df9d0195fcd994e2ed536dcc3f5f0'  
WEATHER_BASE_URL = 'https://api.openweathermap.org/data/2.5/weather'
##WEATHER_API_KEY = '548a3098af2c73560ffec66413a9edc2' 
##WEATHER_BASE_URL = 'https://api.openweathermap.org/data/2.5/weather'

blacklisted_tokens = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in blacklisted_tokens

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    city = db.Column(db.String(100))
    country = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'city': self.city,
            'country': self.country,
            'latitude': self.latitude,
            'longitude': self.longitude
        }

with app.app_context():
    db.create_all()

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def get_weather_data(city=None, country=None, lat=None, lon=None):
    """Fetch weather data from OpenWeatherMap API"""
    if not WEATHER_API_KEY or WEATHER_API_KEY == '548a3098af2c73560ffec66413a9edc2':
        return {
            'location': f"{city}, {country}" if city and country else f"Lat: {lat}, Lon: {lon}",
            'temperature': 22,
            'feels_like': 25,
            'humidity': 65,
            'condition': 'Clear Sky',
            'wind_speed': 3.5,
            'pressure': 1013,
            'description': 'Mock weather data - Please add your OpenWeatherMap API key'
        }
    
    try:
        if lat and lon:
            params = {
                'lat': lat,
                'lon': lon,
                'appid': WEATHER_API_KEY,
                'units': 'metric'
            }
        else:
            params = {
                'q': f"{city},{country}" if country else city,
                'appid': WEATHER_API_KEY,
                'units': 'metric'
            }
        
        response = requests.get(WEATHER_BASE_URL, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'location': data['name'] + ', ' + data['sys']['country'],
                'temperature': round(data['main']['temp']),
                'feels_like': round(data['main']['feels_like']),
                'humidity': data['main']['humidity'],
                'condition': data['weather'][0]['main'],
                'wind_speed': data['wind']['speed'],
                'pressure': data['main']['pressure'],
                'description': data['weather'][0]['description'].title()
            }
        else:
            return None
    except Exception as e:
        print(f"Weather API Error: {e}")
        return None


@app.route('/')
def index():
    return render_template('log_reg.html')

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        city = data.get('city', '').strip()
        country = data.get('country', '').strip()
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        if not ((city and country) or (latitude and longitude)):
            return jsonify({'error': 'Please provide either city & country or latitude & longitude'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        user = User(email=email)
        user.set_password(password)
        
        if city and country:
            user.city = city
            user.country = country
        
        if latitude and longitude:
            user.latitude = float(latitude)
            user.longitude = float(longitude)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'message': 'User registered successfully'}), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        access_token = create_access_token(identity=str(user.id))
        
        return jsonify({
            'token': access_token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/weather', methods=['GET'])
@jwt_required()
def get_weather():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        print("user: ",user,user.latitude,user.longitude,user.city,user.country,user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.latitude and user.longitude:
            weather_data = get_weather_data(lat=user.latitude, lon=user.longitude)
        elif user.city and user.country:
            weather_data = get_weather_data(city=user.city, country=user.country)
        else:
            return jsonify({'error': 'No location set. Please update your location.'}), 400
        
        if not weather_data:
            return jsonify({'error': 'Unable to fetch weather data'}), 500
        
        return jsonify(weather_data), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch weather data'}), 500

@app.route('/api/update-location', methods=['PUT'])
@jwt_required()
def update_location():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        city = data.get('city')
        country = data.get('country')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        if not ((city and country) or (latitude and longitude)):
            return jsonify({'error': 'Please provide either city & country or latitude & longitude'}), 400
        
        if city and country:
            user.city = city.strip()
            user.country = country.strip()
            user.latitude = None
            user.longitude = None
        
        if latitude and longitude:
            user.latitude = float(latitude)
            user.longitude = float(longitude)
            user.city = None
            user.country = None
        
        db.session.commit()
        
        return jsonify({'message': 'Location updated successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update location'}), 500

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        blacklisted_tokens.add(jti)
        return jsonify({'message': 'Successfully logged out'}), 200
    except Exception as e:
        return jsonify({'error': 'Logout failed'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)