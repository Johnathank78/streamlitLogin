import streamlit as st
from sqlalchemy import create_engine, text
import hashlib
import traceback
import re
import pandas
import uuid

# Create the SQL connection to pets_db as specified in your secrets file
engine = create_engine("sqlite:///login.db")
conn = engine.connect()

# Insert some data with conn.session.
with conn as s:
    s.execute(text('''
        CREATE TABLE IF NOT EXISTS users (
            uuid TEXT PRIMARY KEY, 
            name TEXT, 
            lastname TEXT, 
            email TEXT UNIQUE, 
            password TEXT
        );
    '''))
    s.commit()

# Initialize session state for form toggle if it's not already set
if 'show_signup' not in st.session_state:
    st.session_state.show_signup = True

if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False

if 'user_info' not in st.session_state:
    st.session_state.user_info = False

if 'show_change_password' not in st.session_state:
    st.session_state.show_change_password = False

computedStyle = """
            <style>
                div.block-container, div.block-container *, 
                .stTextInput, 
                .stButton {
                    border: none !important;
                }

                .stButton>button:not(button[kind="primary"]), 
                .stButton>button:hover:not(button[kind="primary"]:hover), 
                .stButton>button:focus:not(button[kind="primary"]:focus) {
                    width: 100% !important;
                    background-color: #FF4B4B !important;
                    color: white !important;
                }

                button[kind="primary"] {
                    width: 100% !important;
                    background: none!important;
                    border: none;
                    padding: 0!important;
                    color: grey !important;
                    text-decoration: none;
                    cursor: pointer;
                    border: none !important;
                }
                
                button[kind="primary"]:hover {
                    text-decoration: none;
                    color: grey !important;
                    background-color: unset !important
                }

                button[kind="primary"]:focus {
                    outline: none !important;
                    box-shadow: none !important;
                    color: grey !important;
                }
                
                .stButton > button:active {
                    filter: brightness(130%);
                }

            </style>
        """

computedStyle2 = """
            <style>
                div.block-container, div.block-container *, 
                .stTextInput, 
                .stButton {
                    border: none !important;
                }

                div.block-container{
                    transform: translateY(25%);
                }
                
                button[kind="secondary"]{
                    width: 100% !important;
                    background-color: unset !important;
                    color: #FF4B4B !important;
                    border: solid 3px #FF4B4B !important;
                    font-weight: 800 !important;
                }

                button[kind="primary"] {
                    width: 100% !important;
                    background-color: #FF4B4B !important;
                    color: white !important;
                }
                
                button[kind="primary"]:focus {
                    outline: none !important;
                    box-shadow: none !important;
                    color: white !important;
                }
                
                .stButton > button:active {
                    filter: brightness(130%);
                }

            </style>
        """

st.cache_data.clear()

# Email validation function
def is_valid_email(email):
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.fullmatch(email_regex, email)

# Function to check if the email is already registered
def is_email_registered(email, conn):
    result = conn.execute(f"SELECT * FROM users WHERE email = '{email}'").fetchone()
    s.commit()
    return len(result) > 0

# Function to authenticate the user and fetch user details
def authenticate_and_fetch_user_details(email, password, conn):
    user = conn.execute(f"SELECT * FROM users WHERE email = '{email}'").fetchone()
    s.commit()
    if len(user) == 0:
        return None  # User not found
    user = user.iloc[0]  # Assuming email is unique and only one record is fetched
    if hashlib.sha256(password.encode('utf-8')).hexdigest() == user['password']:
        return user  # Return user details if password is correct
    return None  # Return None if password is incorrect

# Function to delete a user by UUID
def delete_user_by_uuid(user_uuid, conn):
    try:
        with conn as s:
            # SQL to delete user
            s.execute(text('''
                DELETE FROM users WHERE uuid = :uuid;
            '''), {'uuid': user_uuid})
            s.commit()
        return True, "User successfully deleted."
    except Exception as e:
        # Handle any exceptions that occur
        print(f"An error occurred: {e}")
        return False, f"An error occurred: {e}"
    
# Function to change a user's password by UUID
def change_user_password(user_uuid, new_password, conn):
    try:
        # Hash the new password
        hashed_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()

        with conn as s:
            # SQL to update user's password
            s.execute(text('''
                UPDATE users SET password = :password WHERE uuid = :uuid;
            '''), {
                'uuid': user_uuid,
                'password': hashed_password
            })
            s.commit()
        return True, "Password successfully changed."
    except Exception as e:
        # Handle any exceptions that occur
        print(f"An error occurred: {e}")
        return False, f"An error occurred: {e}"

# ------------ #

# Function to display the SignUp form with validation feedback
def display_signup_form():
    with st.container():
        col1, col2, col3 = st.columns([1,2,1])
        with col2:
            with st.form(key='signup_form'):
                st.title("Register")
                name = st.text_input("Name")
                last_name = st.text_input("Last Name")
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                submit_button = st.form_submit_button(label="Sign Up")

                if submit_button:
                    if name == "" or last_name == "" or email == "" or password == "":
                        st.error("Fill every entries")
                    else:
                        if not is_valid_email(email):
                            st.error("Invalid email format")
                        elif is_email_registered(email.lower(), conn):
                            st.error("Email is already registered")
                        else:
                            try:
                                user_uuid = str(uuid.uuid4())  # Generate a UUID
                                with conn as s:
                                    s.execute(text('''
                                        INSERT INTO users (uuid, name, lastname, email, password) 
                                        VALUES (:uuid, :name, :lastname, :email, :password);
                                    '''), {
                                        'uuid': user_uuid,
                                        'name': name, 
                                        'lastname': last_name, 
                                        'email': email.lower(), 
                                        'password': hashlib.sha256(password.encode('utf-8')).hexdigest()
                                    })
                                    s.commit()
                                st.success("Account created successfully!")
                            except Exception:
                                st.error("An error occurred, please try again later")

        if st.button('Or Sign In', type="primary"):
            st.session_state.show_signup = False
            st.rerun()

# Function to display the SignIn form
def display_signin_form():
    with st.container():
        col1, col2, col3 = st.columns([1,2,1])
        with col2:
            with st.form(key='signin_form'):
                st.title("Login")
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")
                submit_button = st.form_submit_button(label="Sign In")
                    
                if submit_button:
                    user_info = authenticate_and_fetch_user_details(email, password, conn)

                    if email == "" or password == "":
                        st.error("Please enter both email and password.")
                    elif not is_valid_email(email):
                        st.error("Please enter a valid email.")
                    elif user_info is not None:
                        st.session_state.is_logged_in = True  # Update login status
                        st.session_state.user_info = user_info  # Store user info in session state
                        st.rerun()  # Rerun the app to update the display
                    else:
                        st.error("Invalid email/password combination.")

        if st.button('Or Sign Up', type="primary"):
            st.session_state.show_signup = True
            st.rerun()

# Function to display user information and actions
def display_user_info(user):
    with st.container():
        # Display the welcome message with the user's name
        st.title(f"Welcome {user['name']}")

        # Display user information
        st.write(f"###### Name: {user['name']}")
        st.write(f"###### Last Name: {user['lastname']}")
        st.write(f"###### Email: {user['email']}")

        col1, col2 = st.columns(2)
        with col1:
            if st.button('**Change Password**', key='change_password', type="secondary"):
                st.session_state.show_change_password = True
                st.rerun()

        with col2:
            if st.button('Delete Account', key='delete_account', type="primary"):
                delete_user_by_uuid(user["uuid"], conn)
                st.session_state.show_signup = True
                st.session_state.is_logged_in = False
                st.session_state.user_info = False
                st.rerun()

def display_change_password_form():
    col1, col2, col3 = st.columns([1,3,1])
    with col2:
        with st.container():
            with st.form(key='signin_form'):
                st.title("Change Password")
                user_info = st.session_state.user_info
                previous_password = st.text_input("Previous Password", type="password", key="prev_password")
                new_password = st.text_input("New Password", type="password", key="new_password")
                repeat_password = st.text_input("Repeat Password", type="password", key="repeat_password")
                submit_button = st.form_submit_button("Change Password")
        
                if submit_button:
                    if previous_password == "" or new_password == "" or repeat_password == "":
                        st.error("Fill all the entries")
                    elif hashlib.sha256(previous_password.encode('utf-8')).hexdigest() != user_info['password']:
                        st.error('Previous password incorrect')
                    elif new_password != repeat_password:
                       st.error('New password does not match')
                    else:
                        change_user_password(user_info["uuid"], new_password, conn)
                        st.success('Password successfully updated !')

# Main function to render the app
def main():
    if st.session_state.show_change_password:
        st.markdown(computedStyle, unsafe_allow_html=True)
        display_change_password_form()
        return
    
    if st.session_state.is_logged_in:
        # Display user info and actions
        st.markdown(computedStyle2, unsafe_allow_html=True)
        display_user_info(st.session_state.user_info)
        return

    if st.session_state.show_signup:
        st.markdown(computedStyle, unsafe_allow_html=True)
        display_signup_form()
    else:
        st.markdown(computedStyle, unsafe_allow_html=True)
        display_signin_form()

if __name__ == "__main__":
    main()
