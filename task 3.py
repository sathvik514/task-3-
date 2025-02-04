import sqlite3
import bcrypt
import re

# Function to create a new database and table (for demo purposes)
def create_db():
    try:
        connection = sqlite3.connect('secure_login.db')
        cursor = connection.cursor()
        cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT
            )
        ''')
        connection.commit()
        print("Database and table created successfully!")
    except sqlite3.Error as e:
        print(f"Error creating database: {e}")
    finally:
        connection.close()

# Function to securely hash passwords
def hash_password(password):
    try:
        # Generate a salt and hash the password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password
    except Exception as e:
        print(f"Error hashing password: {e}")
        return None

# Function to verify the password
def check_password(hashed_password, password):
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except Exception as e:
        print(f"Error checking password: {e}")
        return False

# Function to register a new user
def register_user(username, password):
    # Validate input (basic example)
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        print("Username can only contain letters, numbers, and underscores.")
        return

    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        return

    # Hash the password
    hashed_password = hash_password(password)
    if not hashed_password:
        print("Password hashing failed.")
        return

    # Insert into database using parameterized queries to prevent SQL injection
    try:
        connection = sqlite3.connect('secure_login.db')
        cursor = connection.cursor()

        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        connection.commit()
        print("User registered successfully!")
    except sqlite3.IntegrityError:
        print("Username already exists.")
    except sqlite3.Error as e:
        print(f"Error inserting data into database: {e}")
    finally:
        connection.close()

# Function to authenticate a user
def authenticate_user(username, password):
    try:
        # Fetch user from database using parameterized query
        connection = sqlite3.connect('secure_login.db')
        cursor = connection.cursor()

        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            stored_password = result[0]
            if check_password(stored_password, password):
                print("Login successful!")
            else:
                print("Invalid password.")
        else:
            print("User not found.")
    except sqlite3.Error as e:
        print(f"Error fetching data from database: {e}")
    finally:
        connection.close()

# Main function to drive the system
def main():
    create_db()  # Ensure the database and table exist

    print("Welcome to Secure Login System")
    
    while True:
        action = input("Do you want to (1) Register or (2) Login? (Enter 1 or 2): ")
        
        if action == '1':  # Register
            username = input("Enter a username: ")
            password = input("Enter a password: ")
            register_user(username, password)
        
        elif action == '2':  # Login
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            authenticate_user(username, password)
        
        else:
            print("Invalid choice. Please enter 1 or 2.")
        
        continue_action = input("Do you want to perform another action? (yes/no): ").lower()
        if continue_action != 'yes':
            print("Goodbye!")
            break

# Run the main function
if __name__ == "__main__":
    main()
