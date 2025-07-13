from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, send_file, jsonify, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import pdfkit
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pathlib import Path
import re
import stripe
from flask_mail import Mail, Message
import pyotp
import qrcode
import io
import base64
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps
from flask_babel import Babel, gettext as _
from sqlalchemy import func

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(Path(__file__).parent, 'instance', 'invoice_db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
babel = Babel(app)
stripe.api_key = 'your_stripe_secret_key'

# ========== MODELS ==========
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16))
    otp_confirmed = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='user')
    clients = db.relationship('Client', backref='user', lazy=True)
    products = db.relationship('Product', backref='user', lazy=True)
    invoices = db.relationship('Invoice', backref='user', lazy=True)
    projects = db.relationship('Project', backref='user', lazy=True)
    expenses = db.relationship('Expense', backref='user', lazy=True)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(50))
    address = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invoices = db.relationship('Invoice', backref='client', cascade='all, delete',lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invoice_items = db.relationship('InvoiceItem', backref='product', cascade='all, delete', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)
    budget = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invoices = db.relationship('Invoice', backref='project', lazy=True)
    expenses = db.relationship('Expense', backref='project', lazy=True)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_number = db.Column(db.String(50), unique=True, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='unpaid')
    tax_rate = db.Column(db.Float, default=0.0)
    discount = db.Column(db.Float, default=0.0)
    notes = db.Column(db.Text)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))

    items = db.relationship('InvoiceItem', backref='invoice', lazy=True, cascade='all, delete')
    is_recurring = db.Column(db.Boolean, default=False)
    recurring_interval = db.Column(db.String(20))
    recurring_end_date = db.Column(db.DateTime)
    next_recurring_date = db.Column(db.DateTime)

    def subtotal(self):
        return sum(item.total() for item in self.items)

    def tax_amount(self):
        return self.subtotal() * (self.tax_rate / 100)

    def total_amount(self):
        return self.subtotal() + self.tax_amount() - self.discount



class InvoiceItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_id = db.Column(db.Integer, db.ForeignKey('invoice.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)

    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

    def total(self):
        return self.quantity * self.price

# ========== HELPER FUNCTIONS ==========
def create_recurring_invoices():
    with app.app_context():
        recurring_invoices = Invoice.query.filter(
            Invoice.is_recurring == True,
            Invoice.next_recurring_date <= datetime.now()  # Fix: use datetime.now() not datetime.datetime.now()
        ).all()
        
        for invoice in recurring_invoices:
            new_invoice = Invoice(
                invoice_number=f"INV-{datetime.now().strftime('%Y%m%d')}-{invoice.id}",
                client_id=invoice.client_id,
                date_created=datetime.now(),
                due_date=invoice.due_date + timedelta(days=30),
                status='unpaid',
                tax_rate=invoice.tax_rate,
                discount=invoice.discount,
                notes=invoice.notes,
                user_id=invoice.user_id,
                project_id=invoice.project_id,
                is_recurring=True,
                recurring_interval=invoice.recurring_interval
            )
            
            db.session.add(new_invoice)
            db.session.flush()  # Ensure new_invoice.id is available
            
            for item in invoice.items:
                new_item = InvoiceItem(
                    quantity=item.quantity,
                    price=item.price,
                    invoice_id=new_invoice.id,
                    product_id=item.product_id
                )
                db.session.add(new_item)
            
            if invoice.recurring_interval == 'monthly':
                invoice.next_recurring_date += timedelta(days=30)
            elif invoice.recurring_interval == 'yearly':
                invoice.next_recurring_date += timedelta(days=365)
            
            if invoice.recurring_end_date and invoice.next_recurring_date > invoice.recurring_end_date:
                invoice.is_recurring = False
            
            db.session.commit()

def send_invoice_email(invoice):
    msg = Message(
        subject=f"Invoice #{invoice.invoice_number} from {current_user.username}",
        recipients=[invoice.client.email],
        sender=current_user.email
    )
    from datetime import datetime
    msg.html = render_template('email_invoice.html', invoice=invoice, now=datetime.now())

    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email: {str(e)}")
        return False

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_locale():
    return request.accept_languages.best_match(['en', 'ar'])

# ========== AUTHENTICATION ==========
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Validation
        if not all([username, email, password]):
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('Invalid username format.', 'error')
            return redirect(url_for('register'))

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash('Invalid email.', 'error')
            return redirect(url_for('register'))

        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            flash('Password too weak.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(username=username, email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()

        flash('Account created! Confirm your email to login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not all([email, password]):
            flash('All fields are required', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
        
        if user.otp_confirmed:
            session['user_id'] = user.id
            return redirect(url_for('login_2fa'))
        
        login_user(user)
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html', now=datetime.now())

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/login_2fa', methods=['GET', 'POST'])
def login_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or not user.otp_confirmed:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(request.form.get('token')):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid token. Please try again.', 'error')
    
    return render_template('login_2fa.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/setup_2fa')
@login_required
def setup_2fa():
    if current_user.otp_secret is None:
        current_user.otp_secret = pyotp.random_base32()
        db.session.commit()
    
    totp = pyotp.TOTP(current_user.otp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name='Neon Invoice'
    )
    
    img = qrcode.make(provisioning_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('setup_2fa.html', qr_code=img_str)

@app.route('/verify_2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    if request.method == 'POST':
        totp = pyotp.TOTP(current_user.otp_secret)
        if totp.verify(request.form.get('token')):
            current_user.otp_confirmed = True
            db.session.commit()
            flash('2FA setup successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid token. Please try again.', 'error')
    
    return render_template('verify_2fa.html')

# ========== DASHBOARD ==========
@app.route('/dashboard')
@login_required
def dashboard():
    total_invoices = Invoice.query.filter_by(user_id=current_user.id).count()
    paid_invoices = Invoice.query.filter_by(user_id=current_user.id, status='paid').count()
    unpaid_invoices = Invoice.query.filter_by(user_id=current_user.id, status='unpaid').count()
    total_clients = Client.query.filter_by(user_id=current_user.id).count()

    paid_invoices_data = Invoice.query.filter_by(user_id=current_user.id, status='paid').all()
    total_revenue = sum(invoice.total_amount() for invoice in paid_invoices_data)

    now = datetime.now()
    current_month_start = datetime(now.year, now.month, 1)
    prev_month_end = current_month_start - timedelta(days=1)
    prev_month_start = datetime(prev_month_end.year, prev_month_end.month, 1)

    current_month_revenue = sum(
        inv.total_amount() for inv in paid_invoices_data 
        if inv.date_created >= current_month_start
    )
    
    previous_month_revenue = sum(
        inv.total_amount() for inv in paid_invoices_data 
        if prev_month_start <= inv.date_created < current_month_start
    )

    latest_invoices = Invoice.query.filter_by(user_id=current_user.id)\
        .order_by(Invoice.date_created.desc()).limit(5).all()
    
    latest_clients = Client.query.filter_by(user_id=current_user.id)\
        .order_by(Client.id.desc()).limit(5).all()

    return render_template('dashboard.html',
                         name=current_user.username,
                         total_invoices=total_invoices,
                         paid_invoices=paid_invoices,
                         unpaid_invoices=unpaid_invoices,
                         total_clients=total_clients,
                         total_revenue=total_revenue,
                         revenue_comparison={
                             'current_month': current_month_revenue,
                             'previous_month': previous_month_revenue
                         },
                         latest_invoices=latest_invoices,
                         latest_clients=latest_clients)

# ========== CLIENTS ==========
@app.route('/clients')
@login_required
def clients():
    user_clients = Client.query.filter_by(user_id=current_user.id).all()
    return render_template('clients.html', clients=user_clients)

@app.route('/add_client', methods=['GET', 'POST'])
@login_required
def add_client():
    if request.method == 'POST':
        try:
            client = Client(
                name=request.form.get('name', '').strip(),
                email=request.form.get('email', '').strip(),
                phone=request.form.get('phone', '').strip(),
                address=request.form.get('address', '').strip(),
                user_id=current_user.id
            )
            db.session.add(client)
            db.session.commit()
            flash('Client added successfully', 'success')
            return redirect(url_for('clients'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to add client', 'error')
            app.logger.error(f'Add client error: {str(e)}')

    return render_template('add_client.html')

@app.route('/edit_client/<int:client_id>', methods=['GET', 'POST'])
@login_required
def edit_client(client_id):
    client = Client.query.filter_by(id=client_id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        try:
            client.name = request.form.get('name', client.name).strip()
            client.email = request.form.get('email', client.email).strip()
            client.phone = request.form.get('phone', client.phone).strip()
            client.address = request.form.get('address', client.address).strip()
            db.session.commit()
            flash('Client updated successfully', 'success')
            return redirect(url_for('clients'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update client', 'error')
    
    return render_template('edit_client.html', client=client)

@app.route('/delete_client/<int:client_id>')
@login_required
def delete_client(client_id):
    client = Client.query.filter_by(id=client_id, user_id=current_user.id).first_or_404()
    try:
        db.session.delete(client)
        db.session.commit()
        flash('Client deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete client', 'error')
        app.logger.error(f'Delete client error: {str(e)}')
    return redirect(url_for('clients'))

# ========== PRODUCTS ==========
@app.route('/products')
@login_required
def products():
    user_products = Product.query.filter_by(user_id=current_user.id).all()
    return render_template('products.html', products=user_products)

@app.route('/add_product', methods=['POST'])
@login_required
def add_product():
    try:
        product = Product(
            name=request.form.get('name', '').strip(),
            price=float(request.form.get('price', 0)),
            description=request.form.get('description', '').strip(),
            user_id=current_user.id
        )
        db.session.add(product)
        db.session.commit()
        flash('Product added successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to add product', 'error')
        app.logger.error(f'Add product error: {str(e)}')
    return redirect(url_for('products'))

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.filter_by(id=product_id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        try:
            product.name = request.form.get('name', product.name).strip()
            product.price = float(request.form.get('price', product.price))
            product.description = request.form.get('description', product.description).strip()
            db.session.commit()
            flash('Product updated successfully', 'success')
            return redirect(url_for('products'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update product', 'error')
    
    return render_template('edit_product.html', product=product)

@app.route('/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    product = Product.query.filter_by(id=product_id, user_id=current_user.id).first_or_404()
    try:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete product', 'error')
        app.logger.error(f'Delete product error: {str(e)}')
    return redirect(url_for('products'))

# ========== PROJECTS ==========
from datetime import datetime  # خليه فوق في أول الملف بس

@app.route('/projects')
@login_required
def projects():
    user_projects = Project.query.filter_by(user_id=current_user.id).all()
    today = datetime.now().date()
    return render_template('projects.html', projects=user_projects, today=today)

@app.route('/add_project', methods=['GET', 'POST'])
@login_required
def add_project():
    if request.method == 'POST':
        try:
            project = Project(
                name=request.form.get('name', '').strip(),
                description=request.form.get('description', '').strip(),
                start_date=datetime.strptime(request.form['start_date'], '%Y-%m-%d'),
                end_date=datetime.strptime(request.form['end_date'], '%Y-%m-%d') if request.form.get('end_date') else None,
                budget=float(request.form.get('budget', 0)),
                user_id=current_user.id
            )
            db.session.add(project)
            db.session.commit()
            flash('Project added successfully', 'success')
            return redirect(url_for('projects'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to add project', 'error')
            app.logger.error(f'Add project error: {str(e)}')

    return render_template('add_project.html', today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/edit_project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        try:
            project.name = request.form.get('name', project.name).strip()
            project.description = request.form.get('description', project.description).strip()
            project.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
            project.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d') if request.form.get('end_date') else None
            project.budget = float(request.form.get('budget', project.budget))
            db.session.commit()
            flash('Project updated successfully', 'success')
            return redirect(url_for('projects'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update project', 'error')
    
    return render_template('edit_project.html', project=project)

@app.route('/delete_project/<int:project_id>')
@login_required
def delete_project(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    try:
        db.session.delete(project)
        db.session.commit()
        flash('Project deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete project', 'error')
        app.logger.error(f'Delete project error: {str(e)}')
    return redirect(url_for('projects'))

# ========== EXPENSES ==========
@app.route('/expenses')
@login_required
def expenses():
    user_expenses = Expense.query.filter_by(user_id=current_user.id).all()
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('expenses.html', expenses=user_expenses, projects=projects)

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    
    if request.method == 'POST':
        try:
            expense = Expense(
                amount=float(request.form.get('amount', 0)),
                description=request.form.get('description', '').strip(),
                date=datetime.datetime.strptime(request.form['date'], '%Y-%m-%d'),
                category=request.form.get('category', '').strip(),
                project_id=request.form.get('project_id'),
                user_id=current_user.id
            )
            db.session.add(expense)
            db.session.commit()
            flash('Expense added successfully', 'success')
            return redirect(url_for('expenses'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to add expense', 'error')
            app.logger.error(f'Add expense error: {str(e)}')

    return render_template('add_expense.html', projects=projects, today=datetime.datetime.now().strftime('%Y-%m-%d'))

@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    expense = Expense.query.filter_by(id=expense_id, user_id=current_user.id).first_or_404()
    projects = Project.query.filter_by(user_id=current_user.id).all()
    
    if request.method == 'POST':
        try:
            expense.amount = float(request.form.get('amount', expense.amount))
            expense.description = request.form.get('description', expense.description).strip()
            expense.date = datetime.datetime.strptime(request.form['date'], '%Y-%m-%d')
            expense.category = request.form.get('category', expense.category).strip()
            expense.project_id = request.form.get('project_id')
            db.session.commit()
            flash('Expense updated successfully', 'success')
            return redirect(url_for('expenses'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update expense', 'error')
    
    return render_template('edit_expense.html', expense=expense, projects=projects)

@app.route('/delete_expense/<int:expense_id>')
@login_required
def delete_expense(expense_id):
    expense = Expense.query.filter_by(id=expense_id, user_id=current_user.id).first_or_404()
    try:
        db.session.delete(expense)
        db.session.commit()
        flash('Expense deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete expense', 'error')
        app.logger.error(f'Delete expense error: {str(e)}')
    return redirect(url_for('expenses'))

# ========== INVOICES ==========
@app.route('/invoices')
@login_required
def invoices():
    status_filter = request.args.get('status')
    query = Invoice.query.filter_by(user_id=current_user.id)
    
    if status_filter in ['paid', 'unpaid']:
        query = query.filter_by(status=status_filter)
    
    user_invoices = query.order_by(Invoice.date_created.desc()).all()
    return render_template('invoices.html', invoices=user_invoices)

@app.route('/view_invoice/<int:invoice_id>')
@login_required
def view_invoice(invoice_id):
    invoice = Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404()
    return render_template('view_invoice.html', invoice=invoice)

@app.route('/create_invoice', methods=['GET', 'POST'])
@login_required
def create_invoice():
    clients = Client.query.filter_by(user_id=current_user.id).all()
    products = Product.query.filter_by(user_id=current_user.id).all()
    projects = Project.query.filter_by(user_id=current_user.id).all()
    
    if request.method == 'POST':
        try:
            last_invoice = Invoice.query.filter_by(user_id=current_user.id).order_by(Invoice.id.desc()).first()
            new_number = f"INV-{datetime.now().strftime('%Y%m%d')}-{last_invoice.id + 1 if last_invoice else 1}"
            
            invoice = Invoice(
                invoice_number=new_number,
                client_id=request.form['client_id'],
                due_date=datetime.strptime(request.form['due_date'], '%Y-%m-%d'),
                tax_rate=float(request.form.get('tax_rate', 0)),
                discount=float(request.form.get('discount', 0)),
                notes=request.form.get('notes', '').strip(),
                user_id=current_user.id,
                project_id=request.form.get('project_id'),
                is_recurring=bool(request.form.get('is_recurring')),
                recurring_interval=request.form.get('recurring_interval'),
                recurring_end_date=datetime.strptime(request.form['recurring_end_date'], '%Y-%m-%d') if request.form.get('recurring_end_date') else None,
                next_recurring_date=datetime.strptime(request.form['due_date'], '%Y-%m-%d') if request.form.get('is_recurring') else None
            )
            
            db.session.add(invoice)
            db.session.flush()
            
            product_ids = request.form.getlist('product_id[]')
            quantities = request.form.getlist('quantity[]')
            
            for product_id, quantity in zip(product_ids, quantities):
                product = Product.query.get(product_id)
                if product and product.user_id == current_user.id:
                    item = InvoiceItem(
                        invoice_id=invoice.id,
                        product_id=product_id,
                        quantity=int(quantity),
                        price=product.price
                    )
                    db.session.add(item)
            
            db.session.commit()
            flash('Invoice created successfully', 'success')
            
            if request.form.get('generate_pdf'):
                return generate_invoice_pdf(invoice.id)
            
            return redirect(url_for('view_invoice', invoice_id=invoice.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to create invoice: {str(e)}', 'error')
            app.logger.error(f'Invoice creation error: {str(e)}')
    
    return render_template('create_invoice.html', 
                         clients=clients, 
                         products=products,
                         projects=projects,
                         today=datetime.now().strftime('%Y-%m-%d'),
                         default_due_date=(datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'))

def generate_invoice_pdf(invoice_id):
    invoice = Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404()
    rendered = render_template('invoice_pdf.html', invoice=invoice)
    
    options = {
        'enable-local-file-access': None,
        'encoding': 'UTF-8',
        'margin-top': '15mm',
        'margin-right': '15mm',
        'margin-bottom': '15mm',
        'margin-left': '15mm',
    }
    
    try:
        # Common installation paths for wkhtmltopdf
        possible_paths = [r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe']
        
        # Find the first valid path
        wkhtmltopdf_path = None
        for path in possible_paths:
            if os.path.exists(path):
                wkhtmltopdf_path = path
                break
        
        if wkhtmltopdf_path:
            config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)
            pdf = pdfkit.from_string(rendered, False, options=options, configuration=config)
        else:
            # Fallback to system PATH if not found in common locations
            pdf = pdfkit.from_string(rendered, False, options=options)
            
        return send_file(
            BytesIO(pdf),
            download_name=f"invoice_{invoice.invoice_number}.pdf",
            as_attachment=True,
            mimetype='application/pdf'
        )
    except Exception as e:
        flash('Failed to generate PDF. Please ensure wkhtmltopdf is installed.', 'error')
        app.logger.error(f'PDF generation error: {str(e)}')
        return redirect(url_for('view_invoice', invoice_id=invoice.id))

@app.route('/pay_invoice/<int:invoice_id>', methods=['GET', 'POST'])
@login_required
def pay_invoice(invoice_id):
    invoice = Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': f'Invoice {invoice.invoice_number}',
                        },
                        'unit_amount': int(invoice.total_amount() * 100),
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=url_for('payment_success', invoice_id=invoice.id, _external=True),
                cancel_url=url_for('view_invoice', invoice_id=invoice.id, _external=True),
            )
            
            return redirect(checkout_session.url, code=303)
        
        except Exception as e:
            flash(f'Payment processing error: {str(e)}', 'error')
            return redirect(url_for('view_invoice', invoice_id=invoice.id))
    
    return render_template('pay_invoice.html', invoice=invoice)

@app.route('/payment/success/<int:invoice_id>')
@login_required
def payment_success(invoice_id):
    invoice = Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404()
    invoice.status = 'paid'
    db.session.commit()
    flash('Payment successful! Invoice marked as paid.', 'success')
    return redirect(url_for('view_invoice', invoice_id=invoice.id))

@app.route('/send_invoice/<int:invoice_id>')
@login_required
def send_invoice(invoice_id):
    invoice = Invoice.query.filter_by(id=invoice_id, user_id=current_user.id).first_or_404()
    
    if send_invoice_email(invoice):
        flash('Invoice sent successfully!', 'success')
    else:
        flash('Failed to send invoice email', 'error')
    
    return redirect(url_for('view_invoice', invoice_id=invoice.id))

@app.route('/project/<int:project_id>')
@login_required
def project_details(project_id):
    project = Project.query.filter_by(id=project_id, user_id=current_user.id).first_or_404()
    project_invoices = Invoice.query.filter_by(project_id=project_id, user_id=current_user.id).all()
    project_expenses = Expense.query.filter_by(project_id=project_id, user_id=current_user.id).all()
    
    # حساب إجمالي الفواتير والمصروفات
    total_invoiced = sum(invoice.total_amount() for invoice in project_invoices if invoice.status == 'paid')
    total_expenses = sum(expense.amount for expense in project_expenses)
    
    return render_template('project_details.html',
                         project=project,
                         invoices=project_invoices,
                         expenses=project_expenses,
                         total_invoiced=total_invoiced,
                         total_expenses=total_expenses)

# ========== REPORTS ==========
@app.route('/reports')
@login_required
def reports():
    total_invoices = Invoice.query.filter_by(user_id=current_user.id).count()
    paid_invoices = Invoice.query.filter_by(user_id=current_user.id, status='paid').count()
    unpaid_invoices = Invoice.query.filter_by(user_id=current_user.id, status='unpaid').count()

    paid_invoices_data = Invoice.query.filter_by(user_id=current_user.id, status='paid').all()
    total_revenue = 0.0
    monthly_totals = {}

    for inv in paid_invoices_data:
        month = inv.date_created.strftime('%Y-%m')
        amount = inv.total_amount()
        monthly_totals[month] = monthly_totals.get(month, 0) + amount
        total_revenue += amount

    monthly_data = [{"month": month, "total": total} for month, total in sorted(monthly_totals.items())]

    # Top clients
    # ...existing code...
    # Top clients (حساب مجموع كل عميل في بايثون)
    paid_invoices_list = Invoice.query.filter(
        Invoice.user_id == current_user.id,
        Invoice.status == 'paid'
    ).all()

    client_totals = {}
    for inv in paid_invoices_list:
        client_name = inv.client.name
        client_totals[client_name] = client_totals.get(client_name, 0) + inv.total_amount()
    top_clients = sorted(client_totals.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Top products
    top_products = db.session.query(
        Product.name,
        func.sum(InvoiceItem.quantity * InvoiceItem.price).label('total')
    ).join(InvoiceItem).join(Invoice).filter(
        Invoice.user_id == current_user.id,
        Invoice.status == 'paid'
    ).group_by(Product.name).order_by(func.sum(InvoiceItem.quantity * InvoiceItem.price).desc()).limit(5).all()

    return render_template('reports.html',
                           total_invoices=total_invoices,
                           paid_invoices=paid_invoices,
                           unpaid_invoices=unpaid_invoices,
                           total_revenue=total_revenue,
                           monthly_data=monthly_data,
                           top_clients=top_clients,
                           top_products=top_products)

@app.route('/export_reports')
@login_required
def export_reports():
    # Generate Excel report
    # This requires openpyxl or similar library
    # Implementation depends on your specific requirements
    pass

# ========== SETTINGS ==========
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        try:
            current_user.username = request.form.get('username', current_user.username).strip()
            email = request.form.get('email', current_user.email).strip()
            
            if email != current_user.email:
                if User.query.filter_by(email=email).first():
                    flash('Email already registered', 'error')
                else:
                    current_user.email = email
            
            password = request.form.get('password', '').strip()
            if password:
                current_user.password = generate_password_hash(password, method='pbkdf2:sha256')
            
            current_user.role = request.form.get('role', current_user.role)
            
            db.session.commit()
            flash('Settings updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Failed to update settings', 'error')
    
    return render_template('settings.html')

@app.route('/invoices/<int:invoice_id>/pdf')
@login_required
def generate_invoice_pdf(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)

    if invoice.user_id != current_user.id:
        abort(403)

    # مثال سريع على توليد PDF (ممكن تستخدم WeasyPrint, xhtml2pdf, ReportLab, إلخ)
    rendered = render_template('invoice_pdf.html', invoice=invoice)
    pdf = pdfkit.from_string(rendered, False)

    return send_file(BytesIO(pdf), as_attachment=True, download_name=f"Invoice_{invoice.id}.pdf", mimetype='application/pdf')

# ========== API ENDPOINTS ==========
@app.route('/api/clients/search')
@login_required
def search_clients():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    
    clients = Client.query.filter(
        Client.user_id == current_user.id,
        (Client.name.ilike(f'%{query}%') | Client.email.ilike(f'%{query}%'))
    ).limit(10).all()
    
    return jsonify([{
        'id': client.id,
        'name': client.name,
        'email': client.email,
        'phone': client.phone
    } for client in clients])

@app.route('/api/products/search')
@login_required
def search_products():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    
    products = Product.query.filter(
        Product.user_id == current_user.id,
        (Product.name.ilike(f'%{query}%') | Product.description.ilike(f'%{query}%'))
    ).limit(10).all()
    
    return jsonify([{
        'id': product.id,
        'name': product.name,
        'price': product.price,
        'description': product.description
    } for product in products])

# ========== INITIALIZATION ==========
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Start the scheduler for recurring invoices
    scheduler = BackgroundScheduler()
    scheduler.add_job(create_recurring_invoices, 'interval', days=1)
    scheduler.start()
    
    app.run(debug=True)
