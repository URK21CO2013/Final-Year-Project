# Final-Year-Project
# Authentication script used in sdp(Role-based Access control)
import mysql.connector
import getpass
import datetime
import bcrypt  # Make sure to install: pip install bcrypt

# Connect to the database
db = mysql.connector.connect(
    host="localhost",
    user="sdp_controller",
    password="Password@123",
    database="sdp_database_new"
)

cursor = db.cursor()

# User Login Input
username = input("Enter username: ")
password = getpass.getpass("Enter password: ")

# Fetch user_id, password_hash, failed_attempts, role, account_locked
cursor.execute("SELECT id, password_hash, failed_attempts, role, account_locked FROM users WHERE username = %s", (username,))
result = cursor.fetchone()

if result:
    user_id, stored_password_hash, failed_attempts, role, account_locked = result

  if role == 'admin':
      lockout_duration = 30  # Admin accounts unlock after 30 minutes
  elif role == 'guest':
      lockout_duration = 5  # Guest accounts unlock after 10 minutes
  else:
      lockout_duration = 15  # Employee (or default) accounts unlock after 15 minutes

  minutes_since_locked = 0

  # Check if account is locked
  if account_locked:
      # Check if lockout duration has passed
      cursor.execute("SELECT TIMESTAMPDIFF(MINUTE, lockout_time, NOW()) FROM users WHERE id = %s", (user_id,))
      minutes_since_locked = cursor.fetchone()[0]

  if minutes_since_locked is not None and minutes_since_locked >= lockout_duration:
      # Unlock the account only if enough time has passed
      cursor.execute("UPDATE users SET account_locked = 0, failed_attempts = 0, lockout_time = NULL WHERE id = %s", (user_id,))
      db.commit()
      print("✅ Account unlocked. You can now log in.")
      exit()

  if account_locked:
      print("❌ Account is locked due to too many failed login attempts.")
      exit()

  else:
      # Determine lockout threshold based on role
      if role == 'admin':
          lockout_threshold = 3  # Admin gets locked after 3 failed attempts
      elif role == 'guest':
          lockout_threshold = 7  # Guest gets locked after 7 failed attempts
      else:
          lockout_threshold = 5  # Default lockout threshold for other roles

  # Check if the password matches (hash comparison)
  if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
      print("✅ Login Successful!")

  # Reset failed_attempts to 0
  cursor.execute("UPDATE users SET failed_attempts = 0 WHERE username = %s", (username,))
  db.commit()

  # Insert into open_connection table
  ip_address = "127.0.0.1"  # Replace with actual IP if needed
  status = "active"
  cursor.execute(
  "INSERT INTO open_connection (user_id, ip_address, status) VALUES (%s, %s, %s)",
      (user_id, ip_address, status),
          )

  # Insert into access_logs table
  event_type = "Login Success"
  event_time = datetime.datetime.now()
  cursor.execute(
      "INSERT INTO access_logs (user_id, event_type, ip_address, event_time, status) VALUES (%s, %s, %s, %s, %s)",
        (user_id, event_type, ip_address, event_time, status),
      )

  db.commit()  # Commit all successful login actions
  print("[DEBUG] Logged successful login.")

  # Role-based actions
  if role == 'admin':
      print("Welcome Admin! You have full access.")
      # Admin-specific logic here (if any)
  elif role == 'guest':
      print("Welcome Guest! You have limited access.")
      # Guest-specific logic here (if any)
  else:
      print(f"Welcome {role} user!")
      # Any other role-specific logic

  else:
      print("❌ Incorrect Password!")

  # Increment failed_attempts in users table
  new_failed_attempts = failed_attempts + 1
  cursor.execute("UPDATE users SET failed_attempts = %s WHERE username = %s", (new_failed_attempts, username))

  # Lock account if failed attempts exceed role-specific threshold
  if new_failed_attempts >= lockout_threshold:
      cursor.execute("UPDATE users SET account_locked = TRUE WHERE username = %s", (username,))

  # Log failed login attempt
  cursor.execute(
      "INSERT INTO access_logs (user_id, event_type, ip_address, event_time, status) VALUES (%s, %s, %s, %s, %s)",
      (user_id, "Login Failed", "192.168.1.100", datetime.datetime.now(), "failed"),
        )

  db.commit()  # Commit all failed login actions
        print(f"[DEBUG] Failed attempts updated to {new_failed_attempts}")

else:
    print("❌ User not found!")

cursor.close()
db.close()
