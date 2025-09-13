from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_session import Session
from langgraph.graph import START, END, StateGraph
from langchain_core.messages import HumanMessage, BaseMessage, SystemMessage
from typing import TypedDict, Annotated
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph.message import add_messages
from langchain_groq import ChatGroq
import sqlite3
import uuid, datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
from urllib.parse import urlencode
from flask_mail import Mail, Message
import requests
import psycopg2
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config['SESSION_TYPE'] = 'filesystem'
# app.config["SESSION_PERMANENT"] = False
Session(app)


# ---- Mail Config ----
app.config['MAIL_SERVER'] = 'smtp.gmail.com' 
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USER")  
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASS") 
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USER")

mail = Mail(app)

def send_email(to, subject, body):
    try:
        msg = Message(subject, recipients=[to], body=body)
        mail.send(msg)
        return True
    except Exception as e:
        print("Email error:", e)
        return False

# ---------- DB Setup for Users ----------
def get_db_conn_local():
    conn = sqlite3.connect("chatbot.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row  # so results can be accessed like dicts
    cursor = conn.cursor()
    return conn, cursor

DB_URL = os.getenv("DATABASE_URL")
def get_db_conn():
    conn = psycopg2.connect(DB_URL, sslmode='require')
    cursor = conn.cursor()
    return conn, cursor

conn, cursor = get_db_conn()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT,
    email TEXT UNIQUE,
    password TEXT,
    verified BOOLEAN DEFAULT FALSE,
    token TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS user_threads (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    thread_id TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    preview TEXT
)
""")

## slept and woke up
cursor.execute("DELETE FROM user_threads")

conn.commit()
conn.close()

llm = ChatGroq(groq_api_key=os.getenv("Api_key"),  model="llama-3.3-70b-versatile")

class ChatState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]

def chat_node(state: ChatState):
    messages = state['messages']
    if not messages or messages[0].type != "system":
        messages = [SystemMessage( content="You are Kshitij AI, a friendly AI assistant. You were developed by Ashish Gupta.")] + messages
    response = llm.invoke(messages)
    return {"messages": [response]}

checkpointer = SqliteSaver(conn= sqlite3.connect("chatbot.db", check_same_thread=False))

graph = StateGraph(ChatState)
graph.add_node("chat_node", chat_node)
graph.add_edge(START, "chat_node")
graph.add_edge("chat_node", END)

chatbot = graph.compile(checkpointer=checkpointer)


# -------- Flask Routes -------- #
@app.route("/")
def index():
    print(session.get("user_id", None))
    if "user_id" not in session:
       return render_template("login.html")
    return render_template("index.html", username = session['username'])

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")
        
        conn, cursor = get_db_conn()
        cursor.execute("SELECT id, password, verified, username FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        print("LOGIN INFO", user)
        conn.close()
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        user_id, hashed_pw, verified, username = user
        if not check_password_hash(hashed_pw, password):
            return jsonify({"error": "Invalid username or password"}), 401
        if not verified:
            return jsonify({"error": "Account not verified"}), 403
        print(user_id)
        session["user_id"] = user_id
        session['username'] = username
        session['email'] = email
        print(session["user_id"])
        return jsonify({"message": "Login successful"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        hashed_pw = generate_password_hash(password)
        token = secrets.token_urlsafe(32)
        conn, cursor = get_db_conn()
        cursor.execute("INSERT INTO users (username, email, password, token) VALUES (%s, %s, %s, %s)", (username, email, hashed_pw,token))
        conn.commit()
        conn.close()

        
        verify_link = url_for("verify", token=token, _external=True)
        body = f"Hi {username},\n\nPlease verify your account by clicking the link below:\n{verify_link}\n\nThanks,\nKshitij AI"
        send_email(email, "Verify your Kshitij AI account", body)
        print("mail sent")
        return jsonify({"message": "Signup successful. Please verify your email."})
    
    except psycopg2.IntegrityError:
        return jsonify({"error": "Email already exists"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/forgot", methods=["POST"])
def forgot():
    try:
        data = request.json
        email = data.get("email")
        conn, cursor = get_db_conn()
        cursor.execute("SELECT id, username FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        print(user)
        if not user:
            return jsonify({"error": "Email not registered"}), 404
        token = secrets.token_urlsafe(32)
        cursor.execute("UPDATE users SET token=%s WHERE email=%s", (token, email))
        conn.commit()
        conn.close()
        
        reset_link = url_for("forgot_password", token=token, _external=True)
        # todo: send reset password link on mail
        body = f"Hi {user[1]},\n\nPlease reset your password using link below:\n{reset_link}\n\nThanks,\nKshitij AI"
        send_email(email, "Reset Password: Kshitij AI", body)
        print("reset mail sent")
        return jsonify({"message": "Password reset link generated", "reset_link": reset_link})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/verify/<token>", methods=["GET"])
def verify(token):
    try:
        conn, cursor = get_db_conn()
        cursor.execute("SELECT id FROM users WHERE token=%s", (token,))
        user = cursor.fetchone()
        if not user:
            return "Invalid verification link", 400
        cursor.execute("UPDATE users SET verified=TRUE, token=NULL WHERE id=%s", (user[0],))
        conn.commit()
        conn.close()
        return "Account verified! You can now login."
    except Exception as e:
        return str(e), 500
    
@app.route("/forgot_password/<token>", methods=["GET"])
def forgot_password(token):
    return f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Reset Password</title></head>
      <body style="font-family: sans-serif; max-width: 480px; margin: 3rem auto;">
        <h2>Reset your password</h2>
        <p>Enter a new password for your account.</p>
        <form id="resetForm" onsubmit="submitForm(event)">
          <input type="password" id="password" placeholder="New password" required
                 style="width:100%;padding:.6rem;margin:.5rem 0;">
          <button type="submit" style="padding:.6rem 1rem;">Reset Password</button>
        </form>
        <script>
          async function submitForm(e) {{
            e.preventDefault();
            const password = document.getElementById('password').value;
            const res = await fetch('/reset_password', {{
              method: 'POST',
              headers: {{ 'Content-Type': 'application/json' }},
              body: JSON.stringify({{ token: '{token}', password }})
            }});
            const data = await res.json();
            alert(data.message || data.error || 'Done');
            if (data.message) window.location = '/';
          }}
        </script>
      </body>
    </html>
    """

@app.route("/reset_password", methods=["POST"])
def reset_password():
    try:
        data = request.json
        token = data.get("token")
        new_password = data.get("password")
        
        conn, cursor = get_db_conn()
        cursor.execute("SELECT id FROM users WHERE token=%s", (token,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "Invalid or expired token"}), 400
        
        hashed_pw = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password=%s, token=NULL, verified=TRUE WHERE id=%s", (hashed_pw, user[0]))
        conn.commit()
        conn.close()
        return jsonify({"message": "Password reset successful"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# todo: google login set-up
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI" )

@app.route("/google-login")
def google_login():
    query = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "scope": "openid email profile",
        "response_type": "code",
        "access_type": "offline"
    }
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(query)}")

@app.route("/oauth2callback")
def oauth2callback():
    code = request.args.get("code")

    # Exchange code for token
    res = requests.post("https://oauth2.googleapis.com/token", data={
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    })
    tokens = res.json()
    # id_token = tokens["id_token"]

    # Decode token to get user info
    user_info = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }).json()

    email = user_info["email"]
    username = user_info.get("name", "jon Doe")
    print(email, username)
    # Ensure user exists in DB
    conn, cur = get_db_conn()
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    row = cur.fetchone()

    if row:
        user_id = row[0]
    else:
        cur.execute("INSERT INTO users (email, username, password) VALUES (%s, %s, %s) RETURNING id", (email, username, "google-oauth"))
        user_id = cur.fetchone()[0]
        conn.commit()

    cur.close()
    conn.close()

    session['user_id'] = user_id
    session['username'] = username
    session['email'] = email
    return redirect(url_for('index'))


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for('index'))

#------------------------------------------------

@app.route("/chat", methods=["POST"])
def chat():
    try:
        data = request.json
        user_message = data.get("message", "")
        thread_id = data.get("thread_id")  
        if "user_id" not in session:
            return redirect(url_for('index'))
        
        user_id = session["user_id"]

        conn, cursor = get_db_conn()
        if not thread_id: # new thread for new chat
            thread_id = str(uuid.uuid4())  
            cursor.execute("INSERT INTO user_threads (user_id, thread_id, preview) VALUES (%s, %s, %s)", (user_id, thread_id, user_message[:20]+"..."))
            conn.commit()
            conn.close()
        else:
            cursor.execute("SELECT 1 FROM user_threads WHERE user_id=%s AND thread_id=%s", (user_id, thread_id))
            associated = cursor.fetchone()
            conn.close()
            if not associated:
                return "you are not authorised", 403
        
        events = chatbot.stream({"messages": [HumanMessage(content=user_message)]}, config={"configurable": {"thread_id": thread_id}})
        response_text = "Sorry, I didn’t get a response."
        for event in events:
            chat_data = event.get("chat_node")
            if "messages" in chat_data:
                    msgs = chat_data["messages"]
                    if msgs and hasattr(msgs[-1], "content"):
                        response_text = msgs[-1].content

        return jsonify({"thread_id": thread_id, "response": response_text })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Retrieve all saved conversation thread IDs
@app.route("/threads", methods=["GET"])
def list_threads():
    try:    
        if "user_id" not in session:
            return redirect(url_for('index'))
        # all_threads = set()
        # for checkpoint in checkpointer.list(None):
        #     all_threads.add(checkpoint.config['configurable']['thread_id'])
        # return jsonify(list(all_threads))

        user_id = session["user_id"]
        conn, cursor = get_db_conn()
        cursor.execute(
            "SELECT thread_id, created_at, COALESCE(preview, 'conversation') AS preview FROM user_threads WHERE user_id=%s ORDER BY created_at DESC",
            (user_id,)
        )
        rows = cursor.fetchall()
        conn.close()

        threads = [{
            "thread_id": r[0],
            "preview": r[2]
        } for r in rows]

        return jsonify(threads)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Delete all saved threads not using
@app.route("/threads", methods=["DELETE"])
def delete_all_threads():
    try:
        if "user_id" not in session:
            return redirect(url_for('index'))
        
        user_id = session["user_id"]

        # delete threads from DB
        conn, cursor = get_db_conn()
        cursor.execute("SELECT thread_id FROM user_threads WHERE user_id=%s", (user_id,))
        thread_ids = [row[0] for row in cursor.fetchall()]

        cursor.execute("DELETE FROM user_threads WHERE user_id=%s", (user_id,))
        conn.commit()
        conn.close()

        conn, cursor = get_db_conn_local()
        # delete checkpoints for those threads
        for tid in thread_ids:
            cursor.execute("DELETE FROM checkpoints WHERE thread_id=%s", (tid,))
            # delete_checkpoints_by_thread(conn, tid)
        conn.commit()
        conn.close()

        return jsonify({"status": "all conversations deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Fetch all messages from a specific thread
@app.route("/thread/<thread_id>", methods=["GET"])
def get_thread(thread_id):
    try:
        if "user_id" not in session:
            return redirect(url_for('index'))
        
        user_id = session["user_id"]

        # check ownership
        conn, cursor = get_db_conn()
        cursor.execute(
            "SELECT 1 FROM user_threads WHERE user_id=%s AND thread_id=%s",
            (int(user_id), thread_id)
        )
        associated = cursor.fetchone()
        conn.close()
        if not associated:
            return "you are not authorised", 403
        
        state = chatbot.get_state(config={"configurable": {"thread_id": thread_id}})
        msgs = state.values.get("messages", [])
        messages = []
        for msg in msgs:
            if isinstance(msg, HumanMessage):
                role = "user"
            else:
                role = "assistant"
            messages.append({'role': role, 'content': msg.content})
        return jsonify({"thread_id": thread_id, "messages": messages})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Delete a specific thread
@app.route("/thread/<thread_id>", methods=["DELETE"])
def delete_thread(thread_id):
    try:
        if "user_id" not in session:
            return redirect(url_for('index'))
        user_id = session["user_id"]

        # check ownership
        conn, cursor = get_db_conn()
        cursor.execute(
            "SELECT 1 FROM user_threads WHERE user_id=%s AND thread_id=%s",
            (user_id, thread_id)
        )
        associated = cursor.fetchone()
        if not associated:
            conn.close()
            return "you are not authorised", 403
            
        cursor.execute("DELETE FROM user_threads WHERE thread_id=%s", (thread_id,))
        conn.commit()
        conn.close()
        
        conn, cursor = get_db_conn_local()

        cursor.execute("DELETE FROM writes WHERE thread_id=?", (thread_id,))
        cursor.execute("DELETE FROM checkpoints WHERE thread_id=?", (thread_id,))
        conn.commit()
        deleted = cursor.rowcount
        conn.close()
        return jsonify({"status": "deleted", "cnt": deleted, "thread_id": thread_id})
    except Exception as e:
        print("failed delete", e)
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

