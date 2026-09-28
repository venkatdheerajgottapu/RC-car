from functools import wraps
from flask import Flask, render_template, request, redirect, session, flash, url_for, send_file
from flask_mail import Mail, Message
import sqlite3
import bcrypt
import random
import config
import razorpay
import traceback
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


app = Flask(__name__)

# Secret key for session and flash messages
app.secret_key = config.SECRET_KEY


# ---------------------------------------------------------
# SQLITE DATABASE CONNECTION
# ---------------------------------------------------------
def get_db_connection():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Create all SmartCart tables if they do not already exist."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            PRAGMA foreign_keys = ON
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                profile_image TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                product_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                category TEXT,
                price REAL NOT NULL,
                image TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS addresses (
                address_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                full_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                address TEXT NOT NULL,
                city TEXT NOT NULL,
                state TEXT NOT NULL,
                pincode TEXT NOT NULL,
                country TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                order_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                address_id INTEGER,
                razorpay_order_id TEXT,
                razorpay_payment_id TEXT,
                amount REAL NOT NULL,
                payment_status TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (address_id) REFERENCES addresses(address_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS order_items (
                order_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                product_name TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                price REAL NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(order_id),
                FOREIGN KEY (product_id) REFERENCES products(product_id)
            )
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("SQLite database initialized successfully.")

    except Exception as e:
        print("DB Initialization Error:", e)


init_db()


# ---------------------------------------------------------
# AUTHENTICATION DECORATOR
# ---------------------------------------------------------
def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash("Please log in to access the admin dashboard.", "danger")
            return redirect('/admin-login')
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------
# FLASK MAIL CONFIGURATION
# ---------------------------------------------------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)


# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP + SEND OTP
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == 'GET':
        return render_template("admin/admin_signup.html")

    name = request.form.get('name')
    email = request.form.get('email')

    # Check empty fields
    if not name or not email:
        flash("Name and email are required.", "danger")
        return redirect('/admin-signup')

    # 1. Check if admin email already exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT admin_id FROM admin WHERE email = ?",
        (email,)
    )

    existing_admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if existing_admin:
        flash(
            "This email is already registered. Please login instead.",
            "danger"
        )
        return redirect('/admin-signup')

    # 2. Store signup information temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    # 3. Generate OTP
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    # 4. Send OTP email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )

    message.body = (
        f"Your OTP for SmartCart Admin Registration is: {otp}"
    )

    mail.send(message)

    flash("OTP sent to your email!", "success")

    return redirect('/verify-otp')


# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():

    # Prevent direct access without signup
    if 'signup_email' not in session:
        flash("Please signup first.", "danger")
        return redirect('/admin-signup')

    return render_template("admin/verify_otp.html")


# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():

    # Get submitted values
    user_otp = request.form.get('otp')
    password = request.form.get('password')

    # Check fields
    if not user_otp or not password:
        flash("OTP and password are required.", "danger")
        return redirect('/verify-otp')

    # Check session data
    stored_otp = session.get('otp')
    signup_name = session.get('signup_name')
    signup_email = session.get('signup_email')

    if not stored_otp or not signup_name or not signup_email:
        flash("Signup session expired. Please signup again.", "danger")
        return redirect('/admin-signup')

    # Compare OTP
    if str(stored_otp) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    )

    # Insert admin into database
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO admin (name, email, password)
        VALUES (?, ?, ?)
        """,
        (
            signup_name,
            signup_email,
            hashed_password.decode('utf-8')
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")

    return redirect('/admin-signup')


# ---------------------------------------------------------
# ROUTE 4: ADMIN LOGIN
# ---------------------------------------------------------
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Display login page
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    # Get login details
    email = request.form.get('email')
    password = request.form.get('password')

    # Check empty fields
    if not email or not password:
        flash("Email and password are required.", "danger")
        return redirect('/admin-login')

    # Connect to database
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT admin_id, name, email, password FROM admin WHERE email = ?",
        (email,)
    )

    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    # Check if email exists
    if not admin:
        flash("Invalid email or password.", "danger")
        return redirect('/admin-login')

    # Check password
    if bcrypt.checkpw(
        password.encode('utf-8'),
        admin['password'].encode('utf-8')
    ):

        # Store admin information in session
        session['admin_id'] = admin['admin_id']
        session['admin_name'] = admin['name']
        session['admin_email'] = admin['email']

        flash("Login successful!", "success")

        return redirect('/admin-dashboard')

    else:
        flash("Invalid email or password.", "danger")
        return redirect('/admin-login')


# ---------------------------------------------------------
# ROUTE 5: ADMIN DASHBOARD
# ---------------------------------------------------------
@app.route('/admin-dashboard', methods=['GET'])
@admin_login_required
def admin_dashboard():

    conn = get_db_connection()
    cursor = conn.cursor()

    # -----------------------------
    # ADMIN COUNT
    # -----------------------------
    cursor.execute("SELECT COUNT(*) AS total FROM admin")
    admin_count = cursor.fetchone()['total']

    # -----------------------------
    # RECENT ADMINS
    # -----------------------------
    cursor.execute("""
        SELECT admin_id, name, email
        FROM admin
        ORDER BY admin_id DESC
        LIMIT 5
    """)
    recent_admins = cursor.fetchall()

    # -----------------------------
    # PRODUCT COUNT
    # -----------------------------
    cursor.execute("SELECT COUNT(*) AS total FROM products")
    product_count = cursor.fetchone()['total']

    # -----------------------------
    # FETCH PRODUCTS
    # -----------------------------
    cursor.execute("""
        SELECT *
        FROM products
        ORDER BY product_id DESC
    """)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/admin_dashboard.html",
        admin_name=session.get('admin_name'),
        admin_count=admin_count,
        recent_admins=recent_admins,
        product_count=product_count,
        products=products
    )


# ---------------------------------------------------------
# ROUTE 6: ADMIN LOGOUT
# ---------------------------------------------------------
@app.route('/admin-logout', methods=['GET'])
def admin_logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect('/admin-login')



import os
import uuid
from werkzeug.utils import secure_filename
# =========================================================
# IMAGE UPLOAD CONFIGURATION
# =========================================================

UPLOAD_FOLDER = 'static/uploads/product_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder automatically if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# =========================================================
# ADMIN PROFILE IMAGE UPLOAD CONFIGURATION
# =========================================================

ADMIN_UPLOAD_FOLDER = 'static/uploads/admin_images'

app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER

os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if the uploaded file has a permitted extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# =========================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE
# =========================================================

@app.route('/admin/add-item', methods=['GET'])
def add_item_page():
    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template('admin/add_item.html')


# =========================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =========================================================

@app.route('/admin/add-item', methods=['POST'])
def add_item():
    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # -----------------------------------------------------
    # 1. GET FORM DATA
    # -----------------------------------------------------
    name = request.form.get('name')
    description = request.form.get('description')
    category = request.form.get('category')
    price = request.form.get('price')
    image_file = request.files.get('image')

    # -----------------------------------------------------
    # 2. VALIDATE PRODUCT DETAILS
    # -----------------------------------------------------
    if not name or not description or not category or not price:
        flash("Please fill all product details!", "danger")
        return redirect('/admin/add-item')

    # Convert and validate price format
    try:
        price = float(price)
        if price <= 0:
            raise ValueError()
    except ValueError:
        flash("Please enter a valid positive price!", "danger")
        return redirect('/admin/add-item')

    # -----------------------------------------------------
    # 3. VALIDATE IMAGE FILE & EXTENSION
    # -----------------------------------------------------
    if image_file is None or image_file.filename == '':
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    if not allowed_file(image_file.filename):
        flash("Invalid image type! Allowed types: png, jpg, jpeg, gif, webp", "danger")
        return redirect('/admin/add-item')

    # -----------------------------------------------------
    # 4. SECURE FILENAME & MAKE IT UNIQUE
    # -----------------------------------------------------
    raw_filename = secure_filename(image_file.filename)
    if not raw_filename:
        flash("Invalid image filename!", "danger")
        return redirect('/admin/add-item')

    # Append UUID to prevent duplicate file collisions
    file_ext = raw_filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4().hex}_{raw_filename}"

    # -----------------------------------------------------
    # 5. CREATE IMAGE PATH & SAVE
    # -----------------------------------------------------
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

    try:
        image_file.save(image_path)
    except Exception as e:
        print("Image Upload Error:", e)
        flash("Unable to upload image!", "danger")
        return redirect('/admin/add-item')

    # -----------------------------------------------------
    # 6. INSERT PRODUCT INTO DATABASE
    # -----------------------------------------------------
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO products (name, description, category, price, image)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, description, category, price, unique_filename)
        )

        conn.commit()

        flash("Product added successfully!", "success")
        return redirect('/admin-dashboard')

    except Exception as e:
        # Rollback database if error occurs
        if conn:
            conn.rollback()

        print("Product Database Error:", e)

        # Delete uploaded image if database insertion fails
        if os.path.exists(image_path):
            os.remove(image_path)

        flash("Error adding product to database!", "danger")
        return redirect('/admin/add-item')

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()




#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')
    return render_template("admin/view_item.html", product=product)

# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id = ?",
        (item_id,)
    )

    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template(
        "admin/update_item.html",
        product=product
    )
# =================================================================
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    new_image = request.files.get('image')

    # Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM products WHERE product_id = ?",
        (item_id,)
    )

    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()

        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # If new image uploaded
    if new_image and new_image.filename != "":

        from werkzeug.utils import secure_filename

        new_filename = secure_filename(new_image.filename)

        new_image_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            new_filename
        )

        new_image.save(new_image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                old_image_name
            )

            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # Keep old image
        final_image_name = old_image_name

    # Update database
    cursor.execute("""
        UPDATE products
        SET name=?,
            description=?,
            category=?,
            price=?,
            image=?
        WHERE product_id=?
    """, (
        name,
        description,
        category,
        price,
        final_image_name,
        item_id
    ))

    conn.commit()

    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")

    return redirect('/admin/item-list')

# =================================================================
# ROUTE 13: UPDATED PRODUCT LIST WITH SEARCH + CATEGORY FILTER
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Fetch category list for dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # 2️⃣ Build dynamic query based on filters
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )


# =================================================================
# ROUTE 14: DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1️⃣ Fetch product to get image name
    cursor.execute(
        "SELECT image FROM products WHERE product_id=?",
        (item_id,)
    )

    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect(request.referrer or '/admin-dashboard')

    image_name = product['image']

    # Delete image from folder
    if image_name:
        image_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            image_name
        )

        if os.path.exists(image_path):
            try:
                os.remove(image_path)
            except Exception as e:
                print("Error deleting image file:", e)

    # 2️⃣ Delete product from DB
    cursor.execute(
        "DELETE FROM products WHERE product_id=?",
        (item_id,)
    )

    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")

    return redirect(request.referrer or '/admin-dashboard')
# =================================================================
# ROUTE 1: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()
    return render_template("admin/admin_profile.html", admin=admin)
# =================================================================
# ROUTE 2: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename != "":
        
        from werkzeug.utils import secure_filename
        new_filename = secure_filename(new_image.filename)

        # Save new image
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)
        new_image.save(image_path)

        # Delete old image
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    if isinstance(hashed_password, bytes):
        hashed_password = hashed_password.decode("utf-8")

    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session name for UI consistency
    session['admin_name'] = name  
    session['admin_email'] = email

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')
#=============END of Admin Side======================================================================
#==================================================USER SIDE=========================================
#=================================================================
# ROUTE: 1 USER Register
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Check if user already exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert new user
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed_password.decode("utf-8"))
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/user-login')
#=================================================================
# ROUTE: 2 USER LOGIN
# =================================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')
#=================================================================
# ROUTE: MAIN STOREFRONT LANDING PAGE
# =================================================================   
@app.route('/')
def home():
    return redirect('/user/products')

#=================================================================
# ROUTE: 3 USER DASHBOARD
# =================================================================   
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    return render_template("user/user_home.html", user_name=session['user_name'])
#=================================================================
# ROUTE: 4 USER Logout 
# =================================================================   
@app.route('/user-logout')
def user_logout():
    
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')
#======================================================
# ROUTE:5 USER PRODUCT LISTING (SEARCH + FILTER)
#======================================================
@app.route('/user/products')
def user_products():
    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Build dynamic SQL
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories
    )
# ============================================================
# ROUTE: USER ADDRESS PAGE
# ============================================================

@app.route('/address')
def address():

    if 'user_id' not in session:
        flash("Please login first.", "warning")
        return redirect('/user-login')

    return render_template('user/address.html')
#========================================
# ROUTE: USER PRODUCT DETAILS PAGE
#========================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)
#==========================================================
# ROUTE ADD ITEM TO CART
#==========================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart

    flash("Item added to cart!", "success")
    return redirect(request.referrer)
#==========================================================
# VIEW CART PAGE
#==========================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)
#=========================================================
# ROUTE: INCREASE QUANTITY
#=========================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    return redirect('/user/cart')
#==========================================================
#ROUTE : DECREASE QUANTITY
#==========================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    return redirect('/user/cart')

#==========================================================
# ROUTE 5: Remove Item Completely
#==========================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart

    flash("Item removed!", "success")
    return redirect('/user/cart')

razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)
# ============================================================
# ROUTE: SAVE DELIVERY ADDRESS
# ============================================================

@app.route('/save-address', methods=['POST'])
def save_address():

    # Check whether user is logged in
    if 'user_id' not in session:
        flash("Please login first.", "warning")
        return redirect('/user-login')

    # Get form data
    full_name = request.form.get('full_name')
    phone = request.form.get('phone')
    address = request.form.get('address')
    city = request.form.get('city')
    state = request.form.get('state')
    pincode = request.form.get('pincode')
    country = request.form.get('country')

    # Basic validation
    if not all([
        full_name,
        phone,
        address,
        city,
        state,
        pincode,
        country
    ]):
        flash("Please fill all address details.", "danger")
        return redirect('/address')

    try:
        # Database connection
        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert address
        query = """
            INSERT INTO addresses
            (user_id, full_name, phone, address, city, state, pincode, country)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """

        values = (
            session['user_id'],
            full_name,
            phone,
            address,
            city,
            state,
            pincode,
            country
        )

        cursor.execute(query, values)
        conn.commit()

        # Get newly created address ID
        address_id = cursor.lastrowid

        # Store address ID in session
        session['address_id'] = address_id

        cursor.close()
        conn.close()

        flash("Address saved successfully!", "success")

        # Go to payment page
        return redirect('/user/pay')

    except Exception as e:

        print("Address Save Error:", e)

        flash("Unable to save address.", "danger")

        return redirect('/address')
# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total amount
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())
    razorpay_amount = int(total_amount * 100)  # convert to paise

    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )
# ------------------------------
# Route: Verify Payment and Store Order
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read values posted from frontend
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # Build verification payload required by Razorpay client.utility
    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        # This will raise an error if signature invalid
        razorpay_client.utility.verify_payment_signature(payload)

    except Exception as e:
        # Verification failed
        app.logger.error("Razorpay signature verification failed: ?", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    # Signature verified — now store order and items into DB
    user_id = session['user_id']
    address_id = session.get('address_id')
    cart = session.get('cart', {})

    if not cart:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    # Calculate total amount (ensure same as earlier)
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # DB insert: orders and order_items
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert into orders table including address_id
        cursor.execute("""
            INSERT INTO orders (user_id, address_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, address_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid'))

        order_db_id = cursor.lastrowid  # newly created order's primary key

        # Insert all items
        for pid_str, item in cart.items():
            product_id = int(pid_str)
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (order_db_id, product_id, item['name'], item['quantity'], item['price']))

        # Commit transaction
        conn.commit()

        # Clear cart and temporary razorpay order id
        session.pop('cart', None)
        session.pop('razorpay_order_id', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        # Rollback and log error
        conn.rollback()
        app.logger.error("Order storage failed: ?\n?", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()
#=================================================================================
# Order-Success
#=================================================================================
@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT o.*, 
               COALESCE(a.full_name, u.name) AS name,
               a.full_name, a.phone, a.address, a.city, a.state, a.pincode, a.country
        FROM orders o
        LEFT JOIN addresses a ON o.address_id = a.address_id
        LEFT JOIN users u ON o.user_id = u.user_id
        WHERE o.order_id=? AND o.user_id=?
    """, (order_db_id, user_id))
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/products')

    # Fallback to user's latest address if address_id wasn't linked
    if not order.get('address'):
        cursor.execute("""
            SELECT full_name, phone, address, city, state, pincode, country
            FROM addresses
            WHERE user_id = ?
            ORDER BY address_id DESC LIMIT 1
        """, (user_id,))
        latest_addr = cursor.fetchone()
        if latest_addr:
            order.update({
                'name': latest_addr['full_name'],
                'phone': latest_addr['phone'],
                'address': latest_addr['address'],
                'city': latest_addr['city'],
                'state': latest_addr['state'],
                'pincode': latest_addr['pincode'],
                'country': latest_addr['country']
            })

    cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/order_success.html", order=order, items=items)


# =================================================================
# ROUTE: DOWNLOAD PDF INVOICE
# =================================================================
@app.route('/user/download-invoice/<int:order_db_id>')
def download_invoice(order_db_id):
    if 'user_id' not in session:
        flash("Please login to download invoice.", "danger")
        return redirect('/user-login')

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT o.*, 
               COALESCE(a.full_name, u.name) AS customer_name,
               a.phone, a.address, a.city, a.state, a.pincode, a.country,
               u.email AS customer_email
        FROM orders o
        LEFT JOIN addresses a ON o.address_id = a.address_id
        LEFT JOIN users u ON o.user_id = u.user_id
        WHERE o.order_id = ? AND o.user_id = ?
    """, (order_db_id, user_id))
    order = cursor.fetchone()

    if not order:
        cursor.close()
        conn.close()
        flash("Order not found.", "danger")
        return redirect('/user/products')

    # Fallback to latest address if address_id wasn't linked
    if not order.get('address'):
        cursor.execute("""
            SELECT full_name, phone, address, city, state, pincode, country
            FROM addresses
            WHERE user_id = ?
            ORDER BY address_id DESC LIMIT 1
        """, (user_id,))
        latest_addr = cursor.fetchone()
        if latest_addr:
            order['customer_name'] = latest_addr['full_name']
            order['phone'] = latest_addr['phone']
            order['address'] = latest_addr['address']
            order['city'] = latest_addr['city']
            order['state'] = latest_addr['state']
            order['pincode'] = latest_addr['pincode']
            order['country'] = latest_addr['country']

    cursor.execute("SELECT * FROM order_items WHERE order_id = ?", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    # Generate PDF in memory buffer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'InvoiceTitle',
        parent=styles['Heading1'],
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0077ff'),
        spaceAfter=5
    )
    subtitle_style = ParagraphStyle(
        'InvoiceSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#555555')
    )
    body_style = ParagraphStyle(
        'InvoiceBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#333333')
    )
    header_th_style = ParagraphStyle(
        'HeaderTh',
        parent=styles['Normal'],
        fontSize=10,
        leading=12,
        textColor=colors.white,
        fontName='Helvetica-Bold'
    )

    story = []

    # Header section
    header_data = [
        [
            Paragraph("<b>SmartCart</b><br/><font size=9 color='#666'>Your Smart Online Store</font>", title_style),
            Paragraph(f"<b>TAX INVOICE</b><br/>Order #: {order['order_id']}<br/>Date: {str(order['created_at'])[:10]}", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[300, 240])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (1,0), (1,0), 'RIGHT'),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0077ff'), spaceBefore=5, spaceAfter=15))

    # Addresses & Details Section
    cust_name = order.get('customer_name') or 'Customer'
    cust_addr = order.get('address') or 'N/A'
    cust_city = order.get('city') or ''
    cust_state = order.get('state') or ''
    cust_pincode = order.get('pincode') or ''
    cust_phone = order.get('phone') or 'N/A'
    cust_email = order.get('customer_email') or 'N/A'

    addr_text = f"<b>{cust_name}</b><br/>{cust_addr}<br/>{cust_city}, {cust_state} - {cust_pincode}<br/>Phone: {cust_phone}<br/>Email: {cust_email}"
    order_info = f"<b>Payment ID:</b> {order.get('razorpay_payment_id', 'N/A')}<br/><b>Payment Status:</b> {str(order.get('payment_status', 'paid')).upper()}<br/><b>Razorpay Order ID:</b> {order.get('razorpay_order_id', 'N/A')}"

    details_data = [
        [
            Paragraph("<b>Delivery Address:</b><br/><br/>" + addr_text, body_style),
            Paragraph("<b>Order & Payment Details:</b><br/><br/>" + order_info, body_style)
        ]
    ]
    details_table = Table(details_data, colWidths=[265, 265])
    details_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f9fbfd')),
        ('PADDING', (0,0), (-1,-1), 10),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#d0dbe5')),
    ]))
    story.append(details_table)
    story.append(Spacer(1, 20))

    # Items Table Header
    table_data = [
        [
            Paragraph("<b>Item Description</b>", header_th_style),
            Paragraph("<b>Qty</b>", header_th_style),
            Paragraph("<b>Unit Price (Rs.)</b>", header_th_style),
            Paragraph("<b>Total (Rs.)</b>", header_th_style)
        ]
    ]

    total_calc = 0
    for item in items:
        p_name = item.get('product_name', 'Product')
        qty = item.get('quantity', 1)
        price = float(item.get('price', 0))
        subtotal = qty * price
        total_calc += subtotal
        table_data.append([
            Paragraph(p_name, body_style),
            Paragraph(str(qty), body_style),
            Paragraph(f"{price:.2f}", body_style),
            Paragraph(f"{subtotal:.2f}", body_style)
        ])

    grand_total = float(order.get('amount') or total_calc)
    table_data.append([
        Paragraph("<b>Total Amount Paid</b>", body_style),
        "", "",
        Paragraph(f"<b>Rs. {grand_total:.2f}</b>", body_style)
    ])

    items_table = Table(table_data, colWidths=[260, 60, 105, 105])
    items_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0077ff')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-2), 0.5, colors.HexColor('#e0e0e0')),
        ('SPAN', (0, -1), (2, -1)),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor('#eef5fc')),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
    ]))

    story.append(items_table)
    story.append(Spacer(1, 30))

    # Footer note
    story.append(Paragraph("<font color='#777777' size=9>Thank you for shopping with <b>SmartCart</b>! This is a computer generated invoice.</font>", body_style))

    doc.build(story)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Invoice_Order_{order_db_id}.pdf",
        mimetype='application/pdf'
    )


# =================================================================
# ROUTE: VIEW MY ORDERS
# =================================================================

@app.route('/user/my-orders')
def my_orders():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user/login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT order_id, amount, payment_status, created_at
        FROM orders
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,))

    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('user/my_orders.html', orders=orders)


# ---------------------------------------------------------
# RUN APP
# ---------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
