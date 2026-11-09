import os
import datetime
import secrets
import time
import json
from urllib.parse import urlsplit
from flask import Flask, request, jsonify, Response, stream_with_context
import psycopg
from psycopg_pool import ConnectionPool
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import ollama
import logging
from werkzeug.exceptions import HTTPException
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

exception_origins = ["localhost:5173", "192.168.1.104:5001"]

# Rate limit constants (strings, not functions)
GENERAL_LIMIT = "10 per minute"
AUTH_LIMIT = "5 per minute"
AI_LIMIT = "20 per minute"


def _request_origin_is_exception():
    request_origin = request.headers.get("Origin", "")
    request_parts = urlsplit(request_origin)
    request_host = request_parts.netloc or request_parts.path
    request_host = request_host.rstrip("/").lower()

    for exception_origin in exception_origins:
        origin_parts = urlsplit(
            exception_origin if "://" in exception_origin else f"//{exception_origin}"
        )
        exception_host = (origin_parts.netloc or origin_parts.path).rstrip("/").lower()
        if request_host == exception_host:
            return True
    return False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'ba34581ef0b74fad83935fb7fc332c866f991906d7b50aa1911fa7a973f6fcf6')
CORS(app)
jwt = JWTManager(app=app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address
)


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        logger.warning("HTTP error %s: %s", error.code, error.description)
        return error
    logger.exception("Unhandled application error")
    return jsonify({"success": False, "answer": "", "reason": "error in system"}), 500

DATABASE_URL = os.environ.get('DATABASE_URL', "postgresql://neondb_owner:npg_4IcC8PxyJkgh@ep-shiny-frog-aptm8um4-pooler.c-7.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is missing!")

pool = ConnectionPool(
    conninfo=DATABASE_URL,
    min_size=1,
    max_size=10,
    open=True,
    timeout=30,
    max_idle=300,
    reconnect_timeout=5,
    max_lifetime=3600,
)
DEFAULT_MODEL_CONFIG = {
    "model": "smollm2:135m",
    "keep_alive": -1,
    "options": {
        "temperature": 0.2,
        "num_ctx": 2048,
        "num_predict": 512,
    },
}
DEFAULT_API_KEY = os.environ.get(
    "DEFAULT_API_KEY",
    "csk.ai-default-made-123-0brains-100-vibecoded-by-lazy-programmers",
)


def askAI(question, stream=False, config=None):
    model_config = config or DEFAULT_MODEL_CONFIG
    response = ollama.generate(
        model=model_config["model"],
        prompt=question,
        system=model_config.get("system"),
        stream=stream,
        keep_alive=model_config["keep_alive"],
        options=model_config["options"],
    )
    if stream:
        return response
    return response

password_hasher = PasswordHasher()

def create_and_init_tables():
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS stats (
                    user_id INTEGER PRIMARY KEY,
                    api_calls INTEGER DEFAULT 0,
                    tokens_used INTEGER DEFAULT 0,
                    account_status VARCHAR DEFAULT 'active'
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    user_id INTEGER,
                    api_key VARCHAR UNIQUE,
                    nickname VARCHAR,
                    date_created TIMESTAMPTZ DEFAULT NOW()
                );
            """)
            conn.commit()
    except psycopg.Error:
        logger.exception("Database error while initializing tables")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            pool.putconn(conn)

def create_user(username, email, password):
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE email = %s;", (email,))
            person = cursor.fetchone()

            if person is not None:
                return 'User exists with this mail'

            hashed_password = password_hasher.hash(password)
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s) RETURNING id;",
                (username, email, hashed_password)
            )
            row = cursor.fetchone()
            if row is None:
                conn.rollback()
                return "Internal server error"

            new_user_id = row[0]

            cursor.execute(
                "INSERT INTO stats (user_id, api_calls, tokens_used, account_status) VALUES (%s, 0, 0, 'active');",
                (new_user_id,)
            )
            conn.commit()
            return "success"
    except psycopg.Error as e:
        logger.exception("Database error while creating user")
        if conn:
            conn.rollback()
        print(f'trace here {e}')
        return "Internal server error"
    except Exception as e:
        logger.exception("Unexpected error while creating user")
        if conn:
            conn.rollback()
        print(f'Unexpected create_user error: {type(e).__name__}: {e}')
        return "Internal server error"
    finally:
        if conn:
            pool.putconn(conn)

def checkuser(email, password):
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, password, username FROM users WHERE email = %s;",
                (email,)
            )
            user = cursor.fetchone()

            if user is None:
                return None

            user_id, hashed_password, username = user

            password_hasher.verify(hashed_password, password)
            return {"id": user_id, "username": username}
    except (psycopg.Error, VerifyMismatchError):
        logger.exception("Error while checking user credentials")
        return None
    finally:
        if conn:
            pool.putconn(conn)

@app.route('/')
@limiter.limit(GENERAL_LIMIT)
def index():
    return "hello world"

@app.route('/login', methods=['POST'])
@limiter.limit(AUTH_LIMIT)
def Login():
    data = request.get_json(silent=True)

    if not data or 'email' not in data or 'password' not in data:
        return jsonify({
            "token": None,
            "userId": None,
            "userName": None,
            "success": False,
            "reason": "Missing email or password"
        }), 400

    user = checkuser(email=data['email'], password=data['password'])

    if user:
        token = create_access_token(identity=data['email'])
        return jsonify({
            "token": token,
            "userId": user["id"],
            "userName": user["username"],
            "success": True
        }), 200

    return jsonify({
        "token": None,
        "userId": None,
        "userName": None,
        "success": False,
        "reason": "Invalid credentials"
    }), 401

@app.post('/load_stats')
@limiter.limit(GENERAL_LIMIT)
@jwt_required()
def load_stats():
    data = request.get_json()
    id = data.get('id') if data else None
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM stats WHERE user_id = %s;", (id,))    
            rows = cursor.fetchall()
            stats_list = []
            for row in rows:
                stats_list.append({
                    "user_id": row[0],
                    "api_calls": row[1],
                    "tokens_used": row[2],
                    "account_status": row[3]
                })
            print(f"Stats for user_id {id}: {stats_list}")
            return jsonify(stats_list), 200
    except psycopg.Error:
        logger.exception("Database error while loading stats")
        return jsonify({"success": False, "reason": "Server database error"}), 500
    finally:
        if conn:
            pool.putconn(conn)

@app.post('/load_apis')
@limiter.limit(GENERAL_LIMIT)
@jwt_required()
def load_apis():
    current_user_email = get_jwt_identity()
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT user_id, api_key, nickname, date_created
                FROM api_keys
                WHERE user_id = (
                    SELECT id FROM users WHERE email = %s
                );
            """, (current_user_email,))
            rows = cursor.fetchall()

            api_list = []
            for row in rows:
                api_list.append({
                    "user_id": row[0],
                    "api_key": row[1],
                    "nickname": row[2],
                    "date_created": row[3].isoformat() if row[3] else None
                })

            return jsonify(api_list), 200
    except psycopg.Error:
        logger.exception("Database error while loading API keys")
        return jsonify({"success": False, "reason": "Server database error"}), 500
    finally:
        if conn:
            pool.putconn(conn)


@app.route('/signup', methods=['POST'])
@limiter.limit(AUTH_LIMIT)
def create_account():
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'success': False, 'reason': "Missing required fields"}), 400

    result = create_user(username=data['username'], email=data['email'], password=data['password'])
    if result == "User exists with this mail":
        return jsonify({'success': False, 'reason': "User exists"}), 400
    elif result == 'Internal server error':
        return jsonify({'success': False, 'reason': "Error in server"}), 500
    else:
        return jsonify({'success': True, 'reason': "none"}), 201

@app.post('/generate')
@limiter.limit(GENERAL_LIMIT)
@jwt_required()
def generate_api():
    data = request.get_json(silent=True) or {}
    nickname = data.get('nickname')

    current_user_email = get_jwt_identity()
    conn = None

    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM users WHERE email = %s
            """, (current_user_email,))
            user = cursor.fetchone()
            if user is None:
                return jsonify({"success": False, "reason": "User not found"}), 404

            user_id = user[0]
            new_key = f"sk_{secrets.token_urlsafe(32)}"

            cursor.execute("""
                INSERT INTO api_keys (user_id, api_key, nickname, date_created)
                VALUES (%s, %s, %s, NOW());
            """, (user_id, new_key, nickname))

            conn.commit()
            return jsonify({"success": True, "api_key": new_key, "nickname": nickname}), 201

    except psycopg.Error:
        logger.exception("Database error while generating API key")
        if conn:
            conn.rollback()
        return jsonify({"success": False, "reason": "Server database error"}), 500
    finally:
        if conn:
            pool.putconn(conn)


@app.post('/revoke')
@limiter.limit(GENERAL_LIMIT)
@jwt_required()
def revoke_api():
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key')

    if not api_key:
        return jsonify({"success": False, "reason": "Missing api_key"}), 400

    current_user_email = get_jwt_identity()
    conn = None

    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM users WHERE email = %s
            """, (current_user_email,))
            user = cursor.fetchone()
            if user is None:
                return jsonify({"success": False, "reason": "User not found"}), 404

            user_id = user[0]

            cursor.execute("""
                DELETE FROM api_keys
                WHERE api_key = %s AND user_id = %s
            """, (api_key, user_id))

            conn.commit()

            if cursor.rowcount == 0:
                return jsonify({"success": False, "reason": "API key not found"}), 404

            return jsonify({"success": True, "reason": "API key revoked"}), 200

    except psycopg.Error:
        logger.exception("Database error while revoking API key")
        if conn:
            conn.rollback()
        return jsonify({"success": False, "reason": "Server database error"}), 500
    finally:
        if conn:
            pool.putconn(conn)


@app.post('/edit_api')
@limiter.limit(GENERAL_LIMIT)
@jwt_required()
def edit_api():
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key')
    nickname = data.get('nickname')
    new_api_key = data.get('new_api_key')

    if not api_key:
        return jsonify({"success": False, "reason": "Missing api_key"}), 400

    if nickname is None and new_api_key is None:
        return jsonify({"success": False, "reason": "No fields to update"}), 400

    current_user_email = get_jwt_identity()
    conn = None

    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM users WHERE email = %s
            """, (current_user_email,))
            user = cursor.fetchone()
            if user is None:
                return jsonify({"success": False, "reason": "User not found"}), 404

            user_id = user[0]

            update_fields = []
            params = []

            if nickname is not None:
                if not isinstance(nickname, str) or not nickname.strip():
                    return jsonify({"success": False, "reason": "Invalid nickname"}), 400
                update_fields.append("nickname = %s")
                params.append(nickname.strip())

            if new_api_key is not None:
                if not isinstance(new_api_key, str) or not new_api_key.strip():
                    return jsonify({"success": False, "reason": "Invalid new_api_key"}), 400
                update_fields.append("api_key = %s")
                params.append(new_api_key.strip())

            params.extend([api_key, user_id])

            cursor.execute(f"""
                UPDATE api_keys
                SET {', '.join(update_fields)}
                WHERE api_key = %s AND user_id = %s
            """, tuple(params))

            conn.commit()

            if cursor.rowcount == 0:
                return jsonify({"success": False, "reason": "API key not found"}), 404

            return jsonify({"success": True, "reason": "API key updated"}), 200

    except psycopg.Error:
        logger.exception("Database error while editing API key")
        if conn:
            conn.rollback()
        return jsonify({"success": False, "reason": "Server database error"}), 500
    finally:
        if conn:
            pool.putconn(conn)

@app.post('/add_api_key')
@limiter.limit(GENERAL_LIMIT)
@jwt_required()
def add_api_key():
    data = request.get_json(silent=True) or {}
    nickname = data.get('nickname')
    
    if not nickname or not nickname.strip():
        return jsonify({"success": False, "reason": "Nickname is required"}), 400

    current_user_email = get_jwt_identity()
    conn = None

    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM users WHERE email = %s
            """, (current_user_email,))
            user = cursor.fetchone()
            if user is None:
                return jsonify({"success": False, "reason": "User not found"}), 404

            user_id = user[0]
            new_key = f"csk.ai_{secrets.token_urlsafe(32)}"

            cursor.execute("""
                INSERT INTO api_keys (user_id, api_key, nickname, date_created)
                VALUES (%s, %s, %s, NOW())
                RETURNING api_key, nickname, date_created;
            """, (user_id, new_key, nickname.strip()))

            row = cursor.fetchone()
            conn.commit()

            return jsonify({
                "success": True,
                "api_key": row[0],
                "nickname": row[1],
                "date_created": row[2].isoformat() if row[2] else None
            }), 201

    except psycopg.Error:
        logger.exception("Database error while adding API key")
        if conn:
            conn.rollback()
        return jsonify({"success": False, "reason": "Server database error"}), 500
    finally:
        if conn:
            pool.putconn(conn)

def _is_missing_model(error):
    message = str(error).lower()
    return "model" in message and ("not found" in message or "doesn't exist" in message or "does not exist" in message)


def _token_count(value):
    return value if isinstance(value, int) else 0


def _record_usage(user_id, tokens_used):
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE stats
                SET api_calls = COALESCE(api_calls, 0) + 1,
                    tokens_used = COALESCE(tokens_used, 0) + %s
                WHERE user_id = %s;
            """, (tokens_used, user_id))
            conn.commit()
    except psycopg.Error:
        logger.exception("Database error while recording usage")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            pool.putconn(conn)


@app.route("/askai/", methods=["POST"])
@limiter.limit(AI_LIMIT)
def ask_ai():
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key")
    question = data.get("question")
    if not api_key:
        return jsonify({"success": False, "answer": "", "reason": "API key is required"}), 400
    if not question:
        return jsonify({"success": False, "answer": "", "reason": "Question is required"}), 400

    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cursor:
            if _request_origin_is_exception() and secrets.compare_digest(api_key, DEFAULT_API_KEY):
                key_record = (None,)
            else:
                cursor.execute("""
                    SELECT user_id FROM api_keys WHERE api_key = %s;
                """, (api_key,))
                key_record = cursor.fetchone()
    except psycopg.Error:
        logger.exception("Database error while validating API key")
        return jsonify({"success": False, "answer": "", "reason": "error in system"}), 500
    finally:
        if conn:
            pool.putconn(conn)

    if key_record is None:
        return jsonify({"success": False, "answer": "", "reason": "Invalid API key"}), 401

    user_id = key_record[0]
    user_config = data.get("config") if isinstance(data.get("config"), dict) else {}
    options = dict(DEFAULT_MODEL_CONFIG["options"])
    if isinstance(user_config.get("options"), dict):
        options.update(user_config["options"])
    if isinstance(data.get("options"), dict):
        options.update(data["options"])
    model_config = {
        "model": user_config.get("model", data.get("model", DEFAULT_MODEL_CONFIG["model"])),
        "keep_alive": user_config.get("keep_alive", data.get("keep_alive", DEFAULT_MODEL_CONFIG["keep_alive"])),
        "options": options,
    }
    system = user_config.get("system", data.get("system_instructions"))
    if system:
        model_config["system"] = system

    stream = data.get("stream", True)
    start_time = time.perf_counter()

    try:
        response = askAI(question, stream=stream, config=model_config)
        if not stream:
            answer = response.get("response", "")
            tokens_used = (
                _token_count(response.get("prompt_eval_count")) + _token_count(response.get("eval_count"))
                if isinstance(response, dict) else 0
            )
            _record_usage(user_id, tokens_used)
            return jsonify({
                "success": True,
                "answer": answer,
                "reason": "",
                "tokens_used": tokens_used,
                "response_time_seconds": round(time.perf_counter() - start_time, 2),
            }), 200
    except Exception as error:
        logger.exception("AskAI request failed")
        reason = "model doesn't exist" if _is_missing_model(error) else "error in system"
        status = 404 if reason == "model doesn't exist" else 500
        return jsonify({"success": False, "answer": "", "reason": reason}), status

    def generate():
        answer_parts = []
        tokens_used = 0
        try:
            for chunk in response:
                answer_part = chunk.get("response", "")
                answer_parts.append(answer_part)
                prompt_tokens = chunk.get("prompt_eval_count")
                response_tokens = chunk.get("eval_count")
                if prompt_tokens is not None or response_tokens is not None:
                    tokens_used = _token_count(prompt_tokens) + _token_count(response_tokens)
                yield json.dumps({"success": True, "answer": answer_part, "reason": ""}) + "\n"

            _record_usage(user_id, tokens_used)
            yield json.dumps({
                "success": True,
                "answer": "".join(answer_parts),
                "reason": "",
                "tokens_used": tokens_used,
                "response_time_seconds": round(time.perf_counter() - start_time, 2),
            }) + "\n"
        except Exception as error:
            logger.exception("AskAI stream failed")
            reason = "model doesn't exist" if _is_missing_model(error) else "error in system"
            yield json.dumps({"success": False, "answer": "", "reason": reason}) + "\n"

    return Response(stream_with_context(generate()), mimetype="application/x-ndjson")


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)