#Importation of the necessary libraries
import uuid

from bson import ObjectId
from flask import Flask, request, jsonify #Backend
from flask_cors import CORS #Cross-Origin requests as a security measure
from pymongo import MongoClient #Use of the database
import bcrypt #Password hash library
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity #For the use of JWT as an authentication system


#Flask app configuration
app = Flask("Ricette")
CORS(app) #Enable for all routes

#Definition of the secret for authentication with JWT
app.config['JWT_SECRET_KEY'] = 'secret_key' #Change with an environment variable
jwt = JWTManager(app) #Initialization of JWT

#Class to manage database connection
class DatabaseManager:
    def __init__(self):
        #Connecting to the mongoDB database
        self.client = MongoClient(
            "mongodb+srv://francesco_cianniello:roberta2022@footmatch.aspfg.mongodb.net/Footmatch?retryWrites=true&w=majority"
        )
        self.db = self.client['ricette']  #Defining the database name
        self.users_collection = self.db['users']  #Collections creation
        self.ricette_collection=self.db['ricette']

#User class to represent users
class User:
    def __init__(self, database_manager):
        self.db_manager = database_manager  #Use of database_manager as a new parameter

    #Method for registering a new user
    def registration(self, name, surname, fiscal_code, date_of_birth, username, password):
        #Check that username and password are not blank
        if not username or not password:
            return {"error": "Username and password are required"}, 400

        #Check if the user already exists in the database
        if self.db_manager.users_collection.find_one({"username": username}):
            return {"error": "The user already exists"}, 400

        #Password hash
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        #Entering the user into the database
        self.db_manager.users_collection.insert_one({
            "name": name,
            "surname": surname,
            "fiscal_code": fiscal_code,
            "date_of_birth": date_of_birth,
            "username": username,
            "password": hashed_password.decode('utf-8') #Saving the password as a string
        })
        return {"message": "Registration completed"}, 201

    #Method for logging in
    def login(self, username, password):
        #Check that username and password are not blank
        if not username or not password:
            return {"error": "Username and password are required"}, 400
        #Searching the user in the database
        user = self.db_manager.users_collection.find_one({"username": username})

        #Verify the correctness of the credentials entered
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return {"error": "Invalid credentials"}, 401

        #JWT token generation
        access_token = create_access_token(identity={"username": username})
        return {"access_token": access_token}, 200

#Initializing the DatabaseManager
db_manager = DatabaseManager()

#Initializing the User Class
users = User(db_manager)

#Route for registering a new user
@app.route('/register', methods=['POST'])
def register():
    #Gets JSON data sent from the frontend
    data = request.json
    name = data.get('name')
    surname = data.get('surname')
    fiscal_code = data.get('fiscal_code')
    date_of_birth = data.get('date_of_birth')
    username = data.get('username')
    password = data.get('password')
    #Calling the registration method of the User class
    response, status = users.registration(name, surname, fiscal_code, date_of_birth, username, password)
    return jsonify(response), status #Return HTTP response and status

#Route for user login
@app.route('/login', methods=['POST'])
def login():
    #Gets JSON data sent from the frontend
    data = request.json
    username = data.get('username')
    password = data.get('password')
    #Calling the User Class login method
    response, status = users.login(username, password)
    return jsonify(response), status #Return HTTP response and status

    #Secure route that requires JWT authentication
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity() #Retrieve the user's identity from the JWT token
    return jsonify({"message": f"Welcome {current_user['username']}!"}), 200 #Personalized welcome message

# Route to retrieve user account details
@app.route('/account', methods=['GET'])
@jwt_required()   # Requires JWT for authentication
def get_account():
    current_user = get_jwt_identity()   # Get the current user from the JWT

    if not current_user: # Check if the user exists
        return jsonify({"Error": "User not found"}), 404

    # Retrieve user data from the database
    user = db_manager.users_collection.find_one({"username": current_user["username"]})

    if user:  # Check if the user exists in the database

        user_data = {
            "name": user.get("name"),
            "surname": user.get("surname"),
            "fiscal_code": user.get("fiscal_code"),
            "date_of_birth": user.get("date_of_birth"),
            "username": user.get("username")
        }
        return jsonify(user_data), 200
    else:
        return jsonify({"error": "User not found in database"}), 404

# Recipe management class
class Ricette:
    def __init__(self, database_manager):
        self.db_manager = database_manager

#Initializing the DatabaseManager
db_manager = DatabaseManager()

#Initializing the Ricette Class
ricette2= Ricette(db_manager)

# Route to retrieve all recipes
@app.route('/ricette', methods=['GET'])
@jwt_required()
def get_ricette():
    ricette = db_manager.ricette_collection.find()
    ricette_list = []

    for ricetta in ricette:
        recipe_data = {
            'id': str(ricetta['_id']),   # Convert ObjectId to string
            'recipe_name': ricetta['recipe_name'],
            'preparation_time': ricetta['preparation_time'],
            'type_of_cooking': ricetta['type_of_cooking'],
            'difficulty': ricetta['difficulty'],
            'cost': ricetta['cost'],
            'number_of_ingredients': ricetta['number_of_ingredients'],
            'chef_name': ricetta['chef_name'],
            'image_url': ricetta['image_url'],
            'preparation': ricetta['preparation'],
        }
        ricette_list.append(recipe_data)

    return jsonify(ricette_list), 200

# Route to retrieve a specific recipe by ID
@app.route('/ricette/<recipe_id>', methods=['GET'])
@jwt_required()
def get_ricetta(recipe_id):
    try:
        ricetta = db_manager.ricette_collection.find_one({"_id": recipe_id})  # Search for the recipe by ID

        if ricetta:
            try:
                recipe_data = {
                    'id': ricetta['_id'],
                    'recipe_name': ricetta['recipe_name'],
                    'preparation_time': ricetta['preparation_time'],
                    'type_of_cooking': ricetta['type_of_cooking'],
                    'difficulty': ricetta['difficulty'],
                    'cost': ricetta['cost'],
                    'number_of_ingredients': ricetta['number_of_ingredients'],
                    'chef_name': ricetta['chef_name'],
                    'image_url': ricetta['image_url'],
                    'preparation': ricetta['preparation'],
                }

                # Add ingredients only if they are not None or empty
                for i in range(1, 16):  # From ingredient1 to ingredient15
                    ingredient = ricetta.get(f'ingrediente{i}')
                    if ingredient:   # Add ingredient only if it's not None or an empty string
                        recipe_data[f'ingrediente{i}'] = ingredient

                # After adding all ingredients, return the response
                return jsonify(recipe_data), 200

            except Exception as e:
                # If there is an error while processing the recipe, return the error message
                return jsonify({"error": str(e)}), 500

        else:
            # If the recipe is not found, return a 404 error
            return jsonify({"error": "Recipe not found"}), 404

    except Exception as e:
        # If there is an error with the database query or another issue, return the error message
        return jsonify({"error": str(e)}), 500

@app.route('/ricette/<recipe_id>', methods=['DELETE'])
@jwt_required()
def delete_ricetta(recipe_id):
    try:
        # Try to delete the recipe from the database
        result = db_manager.ricette_collection.delete_one({"_id": recipe_id})

        if result.deleted_count > 0:
            return jsonify({"success": True}), 200
        else:
            return jsonify({"error": "Recipe not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ricette', methods=['POST'])
@jwt_required()
def add_ricetta():
    try:
        # Get data from the frontend
        data = request.json
        recipe_name = data.get('recipe_name')
        preparation_time = data.get('preparation_time')
        type_of_cooking = data.get('type_of_cooking')
        difficulty = data.get('difficulty')
        cost = data.get('cost')
        number_of_ingredients = data.get('number_of_ingredients')
        chef_name = data.get('chef_name')
        image_url = data.get('image_url')
        preparation = data.get('preparation')

        # Extract ingredients from the request body
        ingredients = data.get('ingredients', [])

        # Generate a unique ID for the recipe and converts it to a string
        recipe_id = str(uuid.uuid4())

        # Create the new recipe object
        new_recipe = {
            '_id': recipe_id,
            'recipe_name': recipe_name,
            'preparation_time': preparation_time,
            'type_of_cooking': type_of_cooking,
            'difficulty': difficulty,
            'cost': cost,
            'number_of_ingredients': number_of_ingredients,
            'chef_name': chef_name,
            'image_url': image_url,
            'preparation': preparation,
        }

        # Dynamically add ingredients
        for i, ingredient in enumerate(ingredients, 1):
            new_recipe[f'ingrediente{i}'] = ingredient

        # Insert the recipe into the database
        db_manager.ricette_collection.insert_one(new_recipe)

        return jsonify({"message": "Recipe added successfully", "id": recipe_id}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/save_recipe/<recipe_id>', methods=['POST'])
@jwt_required()
def save_recipe(recipe_id):
    """Save a recipe for the user"""
    current_user = get_jwt_identity()
    username = current_user["username"]

    user = db_manager.users_collection.find_one({"username": username})

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get the user's saved recipes list
    saved_recipes = user.get("saved_recipes", [])

    if recipe_id in saved_recipes:
        return jsonify({"message": "Recipe already saved"}), 400

    saved_recipes.append(recipe_id)
    db_manager.users_collection.update_one({"username": username}, {"$set": {"saved_recipes": saved_recipes}})

    return jsonify({"message": "Recipe saved successfully"}), 200

"""Retrieve all saved recipes for the user"""
@app.route('/saved_recipes', methods=['GET'])
@jwt_required()
def get_saved_recipes():
    current_user = get_jwt_identity()
    username = current_user["username"]

    user = db_manager.users_collection.find_one({"username": username})

    if not user:
        return jsonify({"Error": "User not found"}), 404

    saved_recipes = user.get("saved_recipes", [])
    # Fetch recipes from the database using saved recipe IDs
    recipes = list(db_manager.ricette_collection.find({"_id": {"$in": saved_recipes}}))

    recipes_list = []
    for ricetta in recipes:
        recipes_list.append({
            'id': str(ricetta['_id']),
            'recipe_name': ricetta['recipe_name'],
            'image_url': ricetta['image_url']
        })

    return jsonify(recipes_list), 200

@app.route('/is_saved/<recipe_id>', methods=['GET'])
@jwt_required()
def is_saved(recipe_id):
    """Check if a recipe is already saved by the user"""
    current_user = get_jwt_identity()
    username = current_user["username"]

    user = db_manager.users_collection.find_one({"username": username})

    if not user:
        return jsonify({"error": "User not found"}), 404

    saved_recipes = user.get("saved_recipes", [])
    return jsonify({"saved": recipe_id in saved_recipes}), 200


@app.route('/toggle_save/<recipe_id>', methods=['POST'])
@jwt_required()
def toggle_save(recipe_id):
    """Add or remove a recipe from the saved recipes list"""
    current_user = get_jwt_identity()
    username = current_user["username"]

    user = db_manager.users_collection.find_one({"username": username})

    if not user:
        return jsonify({"error": "User not found"}), 404

    saved_recipes = user.get("saved_recipes", [])

    if recipe_id in saved_recipes:
        saved_recipes.remove(recipe_id)
        saved = False
    else:
        saved_recipes.append(recipe_id)
        saved = True

    db_manager.users_collection.update_one({"username": username}, {"$set": {"saved_recipes": saved_recipes}})

    return jsonify({"saved": saved}), 200

"""Retrieve unique filter options for recipes"""
@app.route('/ricette/filtri', methods=['GET'])
@jwt_required()
def get_filters():
    filters = {}

    try:
        filters['preparation_time'] = db_manager.ricette_collection.distinct('preparation_time')
        filters['type_of_cooking'] = db_manager.ricette_collection.distinct('type_of_cooking')
        filters['difficulty'] = db_manager.ricette_collection.distinct('difficulty')
        filters['cost'] = db_manager.ricette_collection.distinct('cost')
        filters['chef_name'] = db_manager.ricette_collection.distinct('chef_name')

        # Collect unique ingredients across all recipes
        ingredients_set = set()
        for i in range(1, 16):
            ingredient_values = db_manager.ricette_collection.distinct(f'ingrediente{i}')
            ingredients_set.update(filter(None, ingredient_values))   # Remove None or empty values

        filters['ingredients'] = list(ingredients_set)
        return jsonify(filters), 200

    except Exception as e:
        return jsonify({"Error": "Error retrieving filters"}), 500


"""Retrieve recipes based on filters"""
@app.route('/ricette/filtrate', methods=['GET'])
@jwt_required()
def get_filtered_ricette():
    filters = {}
    # Apply filters based on request parameters
    recipe_name = request.args.get('recipe_name')
    if recipe_name:
        filters['recipe_name'] = {'$regex': recipe_name, '$options': 'i'}   # Case-insensitive search

    preparation_time = request.args.get('preparation_time')
    if preparation_time:
        filters['preparation_time'] = preparation_time

    type_of_cooking = request.args.get('type_of_cooking')
    if type_of_cooking:
        filters['type_of_cooking'] = type_of_cooking

    difficulty = request.args.get('difficulty')
    if difficulty:
        filters['difficulty'] = difficulty

    cost = request.args.get('cost')
    if cost:
        filters['cost'] = cost

    number_of_ingredients = request.args.get('number_of_ingredients')
    if number_of_ingredients:
        filters['number_of_ingredients'] = number_of_ingredients

    chef_name = request.args.get('chef_name')
    if chef_name:
        filters['chef_name'] = {'$regex': chef_name, '$options': 'i'}

    ingredient = request.args.get('ingredient')
    if ingredient:
        filters.update({f'ingrediente{i}': {'$regex': ingredient, '$options': 'i'} for i in range(1, 16)})

    ricette = db_manager.ricette_collection.find(filters)
    ricette_list = []

    for ricetta in ricette:
        recipe_data = {
            'id': str(ricetta['_id']),
            'recipe_name': ricetta['recipe_name'],
            'preparation_time': ricetta['preparation_time'],
            'type_of_cooking': ricetta['type_of_cooking'],
            'difficulty': ricetta['difficulty'],
            'cost': ricetta['cost'],
            'number_of_ingredients': ricetta['number_of_ingredients'],
            'chef_name': ricetta['chef_name'],
            'image_url': ricetta['image_url'],
            'preparation': ricetta['preparation'],
        }

        for i in range(1, 16):
            ingredient_key = f'ingrediente{i}'
            if ingredient_key in ricetta:
                recipe_data[ingredient_key] = ricetta[ingredient_key]

        ricette_list.append(recipe_data)

    return jsonify(ricette_list), 200

# Launch the Flask app in debug mode
if __name__ == '__main__':
    app.run(debug=True)  # Debug mode enabled
