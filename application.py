import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Query for user's name
    name = db.execute('SELECT username FROM users WHERE id = ?', session['user_id'])

    # Query for stocks table
    stock_data = db.execute('SELECT * FROM stocks WHERE id = ?', session['user_id'])

    # Query for stock sum
    cash_sum = db.execute('SELECT sum(total_price) FROM stocks WHERE id = ?', session['user_id'])

    # Query for user's cash
    user_cash = db.execute('SELECT cash FROM users WHERE id = ?', session['user_id'])

    # Grand Total
    if not cash_sum[0]['sum(total_price)'] == None:
        grand_total = float(cash_sum[0]['sum(total_price)']) + user_cash[0]['cash']
    else:
        grand_total = user_cash[0]['cash']

    # Homepage
    return render_template('index.html', name=name, stocks=stock_data, user_cash=user_cash, grand=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get('symbol'):
            return apology('symbol missing')

        # Ensure valid symbol
        if lookup(request.form.get('symbol')) == None:
            return apology('Invalid symbol')

        # Ensure shares was submitted
        if not request.form.get('shares'):
            return apology('Missing shares')

        # Ensure shares is integer
        '''def check(string):
            try:
                if int(string) > 0:
                    return True
            except ValueError:
                return False
'''
        if not request.form.get('shares').isnumeric():
            return apology('Invalid Shares')

        # Getting data of stock
        share_price = lookup(request.form.get('symbol'))

        # Query for getting cash of current user
        user_money = db.execute('SELECT cash FROM users WHERE id = ?', session['user_id'])

        # Getting total stock price
        total_stock_price = lookup(request.form.get('symbol'))['price'] * int(request.form.get('shares'))

        # Ensure user can or cannot afford the number of shares at the current price
        if user_money[0]['cash'] < total_stock_price:
            return apology('Your do not have enough money')

        # Checking if stocks exists
        stock_exist = db.execute('SELECT * FROM stocks WHERE symbol = ? AND id = ?',
                                 request.form.get('symbol').upper(), session['user_id'])

        # If stock exists
        if len(stock_exist) == 1:

            # Query to update data in stocks table
            db.execute('UPDATE stocks SET stock_number = stock_number + ?, total_price = total_price + ? WHERE symbol = ? AND id = ?',
                       int(request.form.get('shares')), total_stock_price, request.form.get('symbol').upper(), session['user_id'])

            # Query to insert data in transaction table
            db.execute('INSERT INTO transactions (symbol, id, price, quantity, transaction_type) VALUES (?, ?, ?, ?, ?)',
                       request.form.get('symbol').upper(), session['user_id'], lookup(request.form.get('symbol'))['price'], request.form.get('shares'), 'buy')
        else:

            # Query for inserting data to new table
            db.execute('INSERT INTO stocks (stock_name, stock_number, symbol, id, price, total_price) VALUES (?, ?, ?, ?, ?, ?)',
                       lookup(request.form.get('symbol'))['name'], request.form.get('shares'),
                       lookup(request.form.get('symbol'))['symbol'], session['user_id'],
                       lookup(request.form.get('symbol'))['price'], total_stock_price)

            # Query to insert data in transaction table
            db.execute('INSERT INTO transactions (symbol, id, price, quantity, transaction_type) VALUES (?, ?, ?, ?, ?)',
                       request.form.get('symbol').upper(), session['user_id'],
                       lookup(request.form.get('symbol'))['price'],
                       request.form.get('shares'), 'buy')

        # Query for updating cash
        db.execute('UPDATE users SET cash = ? WHERE id = ?', user_money[0]['cash'] - total_stock_price, session['user_id'])

        # Redirect user to home page
        return redirect('/')

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Query for getting data of current user
    history = db.execute('SELECT * FROM transactions WHERE id = ?', session['user_id'])

    # Passing data to template
    return render_template('history.html', history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == 'POST':

        # Ensure symbol is given
        if not request.form.get('symbol'):
            return apology('missing symbol')

        # Calling lookup function to get data of the symbol
        stock = lookup(request.form.get('symbol'))

        # If data returned is none i.e, stock does not exists
        if stock == None:
            return apology('Invalid Symbol')

        # Passing data of stock to template
        else:
            return render_template('quoted.html', data=stock)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == 'POST':

        # Ensure username was submitted
        if not request.form.get('username'):
            return apology('must provide username')

        # Query database for username
        username = db.execute('SELECT username FROM users WHERE username = ?', request.form.get('username'))

        # Ensure username exists
        if len(username) == 1:
            return apology('username already exists')

        # Getting passwords from form
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        # Ensure password was submitted
        if not password:
            return apology('must provide password')

        # Ensure confirm password was submitted
        elif not confirmation:
            return apology('must provide confirm password')

        # Ensure password matches
        elif password != confirmation:
            return apology('passwords do not match')

        # Query databse for inserting hashed password
        db.execute('INSERT INTO users (username, hash) VALUES (?, ?)',
                   request.form.get('username'), generate_password_hash(request.form.get('password')))

        # Query database for id
        sess = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = sess[0]["id"]

        # Redirect user to home page
        return redirect('/')

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Query for all stocks holding of current user
    stocks = db.execute('SELECT symbol FROM stocks WHERE id = ?', session['user_id'])

    # Query for current user's cash
    user_cash = db.execute('SELECT cash FROM users WHERE id = ?', session['user_id'])

    # User reached route via POST (as by submitting a form via POST)
    if request.method == 'POST':

        # Ensure symbol was submitted
        if not request.form.get('symbol'):
            return apology('missing symbol')

        # Ensure symbol and share was submitted
        if not request.form.get('symbol') and not request.form.get('shares'):
            return apology('missing symbol and shares')

        # Query for stock_number of stock
        stock_no = db.execute('SELECT stock_number FROM stocks WHERE symbol = ? AND id = ?',
                              request.form.get('symbol'), session['user_id'])

        # Ensure shares was submitted
        if not request.form.get('shares'):
            return apology('missing shares')

        # Ensure symbol is integer
        if not request.form.get('shares').isnumeric():
            return apology('invalid shares')

        # Ensure entered stock is less than holding's quantity
        if int(request.form.get('shares')) > int(stock_no[0]['stock_number']):
            return apology('You dont have this much quantity')

        # Ensure entered stock is more than 0
        if int(request.form.get('shares')) <= 0:
            return apology("Please enter valid quantity")

        # Getting price of symbol
        price = lookup(request.form.get('symbol'))['price']

        # Calculating total price of stocks
        total_price = int(request.form.get('shares')) * price

        # If entered all holding stock's number
        if int(request.form.get('shares')) == int(stock_no[0]['stock_number']):
            db.execute('DELETE FROM stocks WHERE symbol = ? AND id = ?', request.form.get('symbol'), session['user_id'])

            # Query to insert data in transaction table
            db.execute('INSERT INTO transactions (symbol, id, price, quantity, transaction_type) VALUES (?, ?, ?, ?, ?)',
                       request.form.get('symbol').upper(), session['user_id'],
                       lookup(request.form.get('symbol'))['price'],
                       request.form.get('shares'), 'sell')

        # If entered less than stock_number
        else:
            db.execute('UPDATE stocks SET stock_number = stock_number - ?, total_price = total_price - ? WHERE symbol = ? AND id = ?',
                       int(request.form.get('shares')),
                       int(request.form.get('shares')) * price, request.form.get('symbol'), session['user_id'])

            # Query to insert data in transaction table
            db.execute('INSERT INTO transactions (symbol, id, price, quantity, transaction_type) VALUES (?, ?, ?, ?, ?)',
                       request.form.get('symbol').upper(), session['user_id'],
                       lookup(request.form.get('symbol'))['price'],
                       request.form.get('shares'), 'sell')

        # Query for updating user cash
        db.execute('UPDATE users SET cash = ? WHERE id = ?', float(user_cash[0]['cash']) + total_price, session['user_id'])

        # Redirect user to homepage
        return redirect('/')

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template('sell.html', stocks=stocks)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_pass():
    '''Change password of user'''

    if request.method == 'POST':

        if not request.form.get('old_password') or not request.form.get('new_password') or not request.form.get('confirmation'):
            return apology('Missing password')

        rows = db.execute('SELECT * FROM users WHERE id = ?', session['user_id'])

        if not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            return apology('Invalid Old password')

        if not request.form.get('new_password') == request.form.get('confirmation'):
            return apology('Passwords do not match')

        db.execute('UPDATE users SET hash = ? WHERE id = ?',
                   generate_password_hash(request.form.get('new_password')), session['user_id'])

        flash("Password Changed!")
        return redirect('/')

    else:
        return render_template('change_password.html')


@app.route("/profile", methods=["GET"])
@login_required
def profile():
    '''Profile of user'''

    users = db.execute('SELECT * FROM users WHERE id = ?', session['user_id'])
    stocks = db.execute('SELECT * FROM stocks WHERE id = ?', session['user_id'])

    if not stocks:
        return render_template('profile.html', users=users)
    else:
        return render_template('profile.html', users=users, stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
