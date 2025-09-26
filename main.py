# Login as alice and bob, return JWT
# see profile


from flask import Flask, request, jsonify
import jwt
import datetime

# Imports for encryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json

app = Flask(__name__)

app.config['SECRET_KEY'] = 'the-super-secret-key-that-no-one-knows'
# Use a fixed-size key derived from the secret key for AES encryption
AES_KEY = app.config['SECRET_KEY'][:16].encode('utf-8')

# Mock user database
user_db = [
  {"id": "001", "username": "alice", "password": "aliceInWonderland", "account_number": "08-765-0001", "balance": 500},
  {"id": "002", "username": "bob", "password": "bobInWonderland", "account_number": "08-765-0002", "balance": 1200},
  {"id": "003", "username": "onigiri", "password": "onigiriInJapan", "account_number": "08-765-0003", "balance": 2000}
]

TRANSACTION_DB = []

def cleanup_expired_transactions():
  """Removes pending transactions older than 5 minutes."""
  global TRANSACTION_DB
  now = datetime.datetime.now(datetime.UTC)
  five_minutes_ago = now - datetime.timedelta(minutes=5)
  
  # Keep transactions that are not pending, or are pending but not expired
  TRANSACTION_DB[:] = [
    t for t in TRANSACTION_DB
    if t['status'] != 'pending' or t['created_at'] > five_minutes_ago
  ]

def encrypt_response(data):
    """Encrypts a dictionary and returns a dictionary with the cipher."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    payload_bytes = json.dumps(data).encode('utf-8')
    ciphertext_bytes = cipher.encrypt(pad(payload_bytes, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ciphertext_bytes).decode('utf-8')
    return {"raw": f"{iv}.{ct}"}

@app.route('/task1/hello', methods=['GET'])
def hello():
  return jsonify({"Hello": "World!"}), 401
  
@app.route('/task2/login', methods=['POST'])
def login():
  if request.method == 'POST':
    body = request.get_json()
    if not body:
      return jsonify({"error": "Request body must be JSON"}), 400
    
    username = body.get('user')
    password = body.get('pass')    
    if not username or not password:
      return jsonify({"error": "Missing required parameter"}), 400
    
    # Find the user in the mock database
    user_found = None
    for user in user_db:
        if user['username'] == username and user['password'] == password:
          user_found = user
          break
    
    # if user and password match with user_db list then return JWT (contain only id and set expired to 2 minutes)
    if user_found:
      print("datetime.datetime.utcnow()", datetime.datetime.now(datetime.UTC))
      print("datetime.now()", datetime.datetime.now())
      print("datetime.timedelta(minutes=2)", datetime.timedelta(minutes=60))
      token = jwt.encode({'id': user_found['id'],
                          'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=60)
                          }, app.config['SECRET_KEY'], algorithm="HS256")
      return jsonify({'token': token}), 200

    # else return error message
    return jsonify({"error": "Invalid credential!"}), 401
  
@app.route('/task2/profile', methods=['GET'])
def profile():
  token = None

  # Check for the token in the 'Authorization' header
  if 'Authorization' in request.headers:
    auth_header = request.headers['Authorization']
    # The header should be in the format "Bearer <token>"
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
      token = parts[1]

  if not token:
      return jsonify({'error': 'Token is missing!'}), 401
  
  try:
    # check JWT (valid signature and not expire)
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    current_user = None
    for user in user_db:
      if user['id'] == data['id']:
        current_user = user
        break

    if not current_user:
      return jsonify({'error': 'User not found!'}), 404
    
    # if valid JWT, then return information (except password) that match id in JWT to user
    user_info = current_user.copy()
    del user_info['password'] # Never return the password
    return jsonify(user_info)
  except jwt.ExpiredSignatureError:
    # else return (invalid JWT)
    return jsonify({'error': 'Token has expired!'}), 401
  except jwt.InvalidTokenError:
    return jsonify({'error': 'Token is invalid!'}), 401

@app.route('/task2/transfer/create', methods=['POST'])
def transfercreate():
  cleanup_expired_transactions()

  # 1. Authentication check
  token = None
  if 'Authorization' in request.headers:
    auth_header = request.headers['Authorization']
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
      token = parts[1]

  if not token:
      return jsonify({'error': 'Token is missing!'}), 401
  
  try:
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    current_user = None
    for user in user_db:
      if user['id'] == data['id']:
        current_user = user
        break
    if not current_user:
      return jsonify({'error': 'User not found!'}), 404
  except jwt.ExpiredSignatureError:
    return jsonify({'error': 'Token has expired!'}), 401
  except jwt.InvalidTokenError:
    return jsonify({'error': 'Token is invalid!'}), 401
  
  # 2. Get UUID from header
  transaction_uuid = request.headers.get('X-Request-ID')
  body = request.get_json()
  if not body:
      return jsonify({"error": "Request body must be JSON"}), 400

  to_account_number = body.get('to')
  amount = body.get('amount')

  if not all([transaction_uuid, to_account_number, amount]):
      return jsonify({"error": "Missing required parameters: X-Request-ID header, to, amount"}), 400

  try:
      amount = float(amount)
      if amount <= 0:
          raise ValueError
  except (ValueError, TypeError):
      return jsonify({"error": "Invalid amount"}), 400

  if any(t['uuid'] == transaction_uuid for t in TRANSACTION_DB):
      return jsonify({"error": "Duplicate transaction"}), 409

  if current_user['balance'] < amount:
      return jsonify({"error": "Insufficient balance"}), 400
  
  if current_user['account_number'] == to_account_number:
      return jsonify({"error": "Cannot transfer to your own account"}), 400

  new_transaction = {
      "uuid": transaction_uuid,
      "from_user_id": current_user['id'],
      "to_account_number": to_account_number,
      "amount": amount,
      "status": "pending",
      "created_at": datetime.datetime.now(datetime.UTC)
  }
  TRANSACTION_DB.append(new_transaction)

  print("===TRANSACTION===")
  print(TRANSACTION_DB)
  print()

  return jsonify({"message": "Transfer initiated successfully. Please confirm."}), 201

@app.route('/task2/transfer/confirm', methods=['POST'])
def transferconfirm():
  cleanup_expired_transactions()

  # 1. Authentication check
  token = None
  if 'Authorization' in request.headers:
    auth_header = request.headers['Authorization']
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
      token = parts[1]

  if not token:
    return jsonify({'error': 'Token is missing!'}), 401
  
  try:
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    current_user = None
    for user in user_db:
      if user['id'] == data['id']:
        current_user = user
        break
    if not current_user:
      return jsonify({'error': 'User not found!'}), 404
  except jwt.ExpiredSignatureError:
    return jsonify({'error': 'Token has expired!'}), 401
  except jwt.InvalidTokenError:
    return jsonify({'error': 'Token is invalid!'}), 401
  
  # 2. Get UUID from header
  transaction_uuid = request.headers.get('X-Request-ID')

  transaction = next((t for t in TRANSACTION_DB if t['uuid'] == transaction_uuid), None)

  if not transaction:
      return jsonify({"error": "Could not find transaction"}), 404
  
  if transaction['status'] != 'pending' or transaction['from_user_id'] != current_user['id']:
      return jsonify({"error": "Invalid transaction or permission denied"}), 403

  if current_user['balance'] < transaction['amount']:
      transaction['status'] = 'failed_insufficient_funds'
      return jsonify({"error": "Insufficient balance at time of confirmation"}), 400

  recipient = next((user for user in user_db if user['account_number'] == transaction['to_account_number']), None)
  if not recipient:
      transaction['status'] = 'failed_recipient_not_found'
      return jsonify({"error": "Recipient account no longer exists"}), 404
  
  current_user['balance'] -= transaction['amount']
  recipient['balance'] += transaction['amount']
  transaction['status'] = 'completed'
  transaction['confirmed_at'] = datetime.datetime.now(datetime.UTC)
  
  return jsonify({"message": "Transfer confirmed successfully", "transaction": transaction}), 200

@app.route('/task3/encrypt', methods=['POST'])
def encrypt_payload():
  body = request.get_json()
  if not body:
    return jsonify({"error": "Request body must be JSON"}), 400
  return jsonify(encrypt_response(body))

@app.route('/task3/decrypt', methods=['POST'])
def decrypt_payload():
  body = request.get_json()
  if not body or 'raw' not in body:
    return jsonify({"error": "Missing 'raw' in request body"}), 400
  
  try:
    # Split IV and ciphertext
    iv_b64, ct_b64 = body['raw'].split('.')
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    
    # Decrypt
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt_bytes = unpad(cipher.decrypt(ct), AES.block_size)
    
    # Convert bytes -> string -> dict
    decrypted_payload = json.loads(pt_bytes.decode('utf-8'))
    return jsonify(decrypted_payload)

  except (ValueError, KeyError, base64.binascii.Error) as e:
    return jsonify({"error": "Invalid cipher text"}), 400

@app.route('/task3/transfer/create', methods=['POST'])
def enctransfercreate():
  cleanup_expired_transactions()
  
  # --- Authentication ---
  token = None
  if 'Authorization' in request.headers:
    auth_header = request.headers['Authorization']
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
      token = parts[1]
  if not token: return jsonify({'error': 'Token is missing!'}), 401
  
  try:
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    current_user = next((u for u in user_db if u['id'] == data['id']), None)
    if not current_user: return jsonify({'error': 'User not found!'}), 404
  except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
    return jsonify({'error': 'Token is invalid or expired!'}), 401

  # --- Decrypt Payload ---
  body = request.get_json()
  if not body or 'raw' not in body:
    return jsonify(encrypt_response({"error": "Missing 'raw' in request body"})), 400
  try:
    iv_b64, ct_b64 = body['raw'].split('.')
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt_bytes = unpad(cipher.decrypt(ct), AES.block_size)
    payload = json.loads(pt_bytes.decode('utf-8'))
  except Exception:
    return jsonify(encrypt_response({"error": "Invalid input text"})), 400
      
  # --- Process Transfer ---
  tran_id = payload.get('tranId')
  to_account_number = payload.get('to')
  amount = payload.get('amount')

  if not all([tran_id, to_account_number, amount]):
    return jsonify(encrypt_response({"error": "Decrypted payload missing tranId, to, or amount"})), 400

  try:
    amount = float(amount)
    if amount <= 0: raise ValueError
  except (ValueError, TypeError):
    return jsonify({"error": "Invalid amount"}), 400

  if any(t['uuid'] == tran_id for t in TRANSACTION_DB):
    return jsonify(encrypt_response({"error": "Duplicate transaction"})), 409
  if current_user['balance'] < amount:
    return jsonify(encrypt_response({"error": "Insufficient balance"})), 400
  if current_user['account_number'] == to_account_number:
    return jsonify(encrypt_response({"error": "Cannot transfer to your own account"})), 400

  new_transaction = {
    "uuid": tran_id,
    "from_user_id": current_user['id'],
    "to_account_number": to_account_number,
    "amount": amount,
    "status": "pending",
    "created_at": datetime.datetime.now(datetime.UTC)
  }
  TRANSACTION_DB.append(new_transaction)

  print("===TRANSACTION===")
  print(TRANSACTION_DB)
  print()

  return jsonify(encrypt_response({"message": "Transfer initiated successfully. Please confirm."})), 201

@app.route('/task3/transfer/confirm', methods=['POST'])
def enctransferconfirm():
  cleanup_expired_transactions()

  # --- Authentication ---
  token = None
  if 'Authorization' in request.headers:
    auth_header = request.headers['Authorization']
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
      token = parts[1]
  if not token: return jsonify({'error': 'Token is missing!'}), 401
  try:
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    current_user = next((u for u in user_db if u['id'] == data['id']), None)
    if not current_user: return jsonify({'error': 'User not found!'}), 404
  except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
    return jsonify({'error': 'Token is invalid or expired!'}), 401

  # --- Decrypt Payload ---
  body = request.get_json()
  if not body or 'raw' not in body:
    return jsonify(encrypt_response({"error": "Missing 'raw' in request body"})), 400
  try:
    iv_b64, ct_b64 = body['raw'].split('.')
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt_bytes = unpad(cipher.decrypt(ct), AES.block_size)
    payload = json.loads(pt_bytes.decode('utf-8'))
  except Exception:
    return jsonify(encrypt_response({"error": "Invalid cipher text"})), 400

  # --- Process Confirmation ---
  tran_id = payload.get('tranId')
  if not tran_id:
    return jsonify(encrypt_response({"error": "Decrypted payload missing tranId"})), 400

  transaction = next((t for t in TRANSACTION_DB if t['uuid'] == tran_id), None)

  if not transaction:
    return jsonify(encrypt_response({"error": "Could not find transaction"})), 404
  if transaction['status'] != 'pending' or transaction['from_user_id'] != current_user['id']:
    return jsonify(encrypt_response({"error": "Invalid transaction or permission denied"})), 403
  if current_user['balance'] < transaction['amount']:
    transaction['status'] = 'failed_insufficient_funds'
    return jsonify(encrypt_response({"error": "Insufficient balance at time of confirmation"})), 400

  recipient = next((user for user in user_db if user['account_number'] == transaction['to_account_number']), None)
  if not recipient:
    transaction['status'] = 'failed_recipient_not_found'
    return jsonify(encrypt_response({"error": "Recipient account no longer exists"})), 404

  current_user['balance'] -= transaction['amount']
  recipient['balance'] += transaction['amount']
  transaction['status'] = 'completed'
  transaction['confirmed_at'] = datetime.datetime.now(datetime.UTC)
  
  return jsonify(encrypt_response({"message": "Transfer confirmed successfully"})), 200

if __name__ == "__main__":
  app.run(debug=True)