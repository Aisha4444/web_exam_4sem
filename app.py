from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import hashlib
from models import db, User, Role, Book, Cover, Genre, Review, BookView
import bleach
from config import Config
from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy import func, desc
import csv
from io import BytesIO, TextIOWrapper
import uuid

app = Flask(__name__)
app.config.from_object(Config)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

db.init_app(app)

with app.app_context():
    db.create_all()

    existing_roles = {role.name for role in Role.query.all()}
    roles_to_add = [
        Role(name='admin', description='Администратор (полный доступ)'),
        Role(name='moderator', description='Модератор (редактирование книг и рецензий)'),
        Role(name='user', description='Пользователь (может оставлять рецензии)')
    ]
    new_roles = [role for role in roles_to_add if role.name not in existing_roles]
    if new_roles:
        db.session.add_all(new_roles)

    if not User.query.filter_by(login='admin').first():
        admin = User(
            login='admin',
            last_name='Admin',
            first_name='System',
            role_id=Role.query.filter_by(name='admin').first().id
        )
        admin.set_password('admin')
        db.session.add(admin)

    if not User.query.filter_by(login='user1').first():
        user1 = User(
            login='user1',
            last_name='Газимагомедова',
            first_name='Аиша',
            role_id=Role.query.filter_by(name='user').first().id
        )
        user1.set_password('userpass')
        db.session.add(user1)

    if not User.query.filter_by(login='moderator1').first():
        moderator1 = User(
            login='moderator1',
            last_name='Газимагомедова',
            first_name='Аиша',
            role_id=Role.query.filter_by(name='moderator').first().id
        )
        moderator1.set_password('modpass')
        db.session.add(moderator1)

    db.session.commit()

    existing_genres = {genre.name for genre in Genre.query.all()}
    genres_to_add = [
        'Фантастика', 'Детектив', 'Роман', 'Поэзия', 'Научная литература',
        'Исторический роман', 'Приключения', 'Триллер', 'Фэнтези', 'Биография',
        'Психология', 'Эссе', 'Документальная литература', 'Юмор', 'Драма',
        'Мистика', 'Классическая литература', 'Публицистика', 'Комиксы', 'Детская литература'
    ]
    new_genres = [Genre(name=name) for name in genres_to_add if name not in existing_genres]
    if new_genres:
        db.session.add_all(new_genres)

    db.session.commit()

def role_required(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Для выполнения данного действия необходимо пройти процедуру аутентификации', 'warning')
                return redirect(url_for('login'))

            if current_user.role.name not in required_roles:
                flash('У вас недостаточно прав для выполнения данного действия', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_cover_file(file_storage):
    filename = secure_filename(file_storage.filename)
    if '.' not in filename:
        raise ValueError('Файл обложки должен иметь расширение')
    ext = filename.rsplit('.', 1)[1].lower()

    if not allowed_file(filename):
        raise ValueError('Недопустимый формат файла обложки')

    file_bytes = file_storage.read()
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    file_storage.seek(0)

    cover = Cover.query.filter_by(md5_hash=md5_hash).first()
    if cover:
        return cover

    cover = Cover(filename='', mime_type=file_storage.mimetype, md5_hash=md5_hash)
    db.session.add(cover)
    db.session.flush()

    cover.filename = f"{cover.id}.{ext}"

    covers_dir = os.path.join(app.static_folder, 'covers')
    os.makedirs(covers_dir, exist_ok=True)
    save_path = os.path.join(covers_dir, cover.filename)

    try:
        file_storage.save(save_path)
    except Exception as e:
        db.session.rollback()
        raise IOError(f"Ошибка при сохранении файла обложки: {e}")
    return cover

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if not current_user.is_authenticated:
        if 'visitor_id' not in session:
            import uuid
            session['visitor_id'] = str(uuid.uuid4())
    page = request.args.get('page', 1, type=int)
    books = Book.query.order_by(Book.year.desc()).paginate(page=page, per_page=10)

    for book in books.items:
        book.review_count = len(book.reviews)
        if book.review_count > 0:
            book.avg_rating = sum(review.rating for review in book.reviews) / book.review_count
        else:
            book.avg_rating = 0

    three_months_ago = datetime.utcnow() - timedelta(days=90)

    popular_books = db.session.query(
        Book,
        func.count(BookView.id).label('views_count')
    ).join(BookView).filter(
        BookView.viewed_at >= three_months_ago
    ).group_by(Book.id).order_by(func.count(BookView.id).desc()).limit(5).all()

    if current_user.is_authenticated:
        recent_views = BookView.query.filter_by(user_id=current_user.id).order_by(BookView.viewed_at.desc()).limit(
            5).all()
    else:
        visitor_id = session.get('visitor_id')
        if visitor_id:
            recent_views = BookView.query.filter_by(session_id=visitor_id) \
                .order_by(BookView.viewed_at.desc()) \
                .limit(5).all()
        else:
            recent_views = []

    recent_books = [view.book for view in recent_views]

    return render_template('index.html', books=books, popular_books=popular_books, recent_books=recent_books)

@app.route('/books/<int:book_id>')
def view_book(book_id):
    book = Book.query.get_or_404(book_id)
    reviews = Review.query.filter_by(book_id=book.id, status='approved').order_by(Review.created_at.desc()).all()
    user_review = None
    can_write_review = False

    if current_user.is_authenticated:
        user_review = Review.query.filter_by(book_id=book.id, user_id=current_user.id).first()
        can_write_review = user_review is None

    if current_user.is_authenticated:
        user_id = current_user.id
        session_id = None
    else:
        if 'visitor_id' not in session:
            session['visitor_id'] = str(uuid.uuid4())
            session.modified = True
        user_id = None
        session_id = session['visitor_id']

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)

    views_count = BookView.query.filter(
        BookView.book_id == book_id,
        BookView.viewed_at >= today_start,
        BookView.viewed_at < today_end,
        ((BookView.user_id == user_id) if user_id else (BookView.session_id == session_id))
    ).count()

    if views_count < 10:
        new_view = BookView(book_id=book_id, user_id=user_id, session_id=session_id)
        db.session.add(new_view)
        db.session.commit()

    return render_template('view_book.html', book=book, reviews=reviews, user_review=user_review, can_write_review=can_write_review)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(login=login).first()

        if not user or not user.check_password(password):
            flash('Невозможно аутентифицироваться с указанными логином и паролем', 'error')
            return redirect(url_for('login'))

        login_user(user, remember=remember)
        next_page = request.args.get('next')
        return redirect(next_page or url_for('index'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/books/new', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def new_book():
    genres = Genre.query.all()
    now = datetime.now()

    if request.method == 'POST':
        try:
            title = request.form['title'].strip()
            author = request.form['author'].strip()
            year = int(request.form['year'])
            publisher = request.form['publisher'].strip()
            pages = int(request.form['pages'])
            description_raw = request.form['description']
            genres_ids = request.form.getlist('genres[]')

            allowed_tags = bleach.sanitizer.ALLOWED_TAGS.union({'p', 'br', 'ul', 'li', 'strong', 'em', 'a'})
            description = bleach.clean(description_raw, tags=allowed_tags, strip=True)

            if 'cover' not in request.files:
                flash('Файл обложки обязателен', 'danger')
                raise ValueError('Файл обложки обязателен')
            cover_file = request.files['cover']
            if cover_file.filename == '':
                flash('Файл обложки обязателен', 'danger')
                raise ValueError('Файл обложки обязателен')

            cover = save_cover_file(cover_file)
            db.session.add(cover)
            db.session.flush()

            book = Book(title=title, author=author, year=year, publisher=publisher, pages=pages,
                        description=description, cover=cover)

            db.session.add(book)

            with db.session.no_autoflush:
                selected_genres = Genre.query.filter(Genre.id.in_(genres_ids)).all()
                book.genres = selected_genres

            db.session.commit()
            flash('Книга успешно добавлена', 'success')
            return redirect(url_for('view_book', book_id=book.id))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Ошибка при добавлении книги: {e}", exc_info=True)
            flash('При сохранении данных возникла ошибка. Проверьте корректность введённых данных.', 'danger')
            return render_template('book_form.html', book=None, genres=genres, now=now)

    return render_template('book_form.html', book=None, genres=genres, now=now)

@app.route('/books/<int:book_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'moderator')
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    genres = Genre.query.all()
    now = datetime.now()

    if request.method == 'POST':
        try:
            book.title = request.form['title'].strip()
            book.author = request.form['author'].strip()
            book.year = int(request.form['year'])
            book.publisher = request.form['publisher'].strip()
            book.pages = int(request.form['pages'])
            description_raw = request.form['description']
            book.description = bleach.clean(
                description_raw,
                tags=bleach.sanitizer.ALLOWED_TAGS.union({'p', 'br', 'ul', 'li', 'strong', 'em', 'a'}),
                strip=True
            )
            genres_ids = request.form.getlist('genres')
            selected_genres = Genre.query.filter(Genre.id.in_(genres_ids)).all()
            book.genres = selected_genres

            db.session.commit()
            flash('Книга успешно обновлена', 'success')
            return redirect(url_for('view_book', book_id=book.id))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Ошибка при редактировании книги: {e}")
            flash('При сохранении данных возникла ошибка. Проверьте корректность введённых данных.', 'danger')
            return render_template('book_form.html', book=book, genres=genres, now=now)

    return render_template('book_form.html', book=book, genres=genres, now=now)

@app.route('/books/<int:book_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    cover_path = os.path.join(app.static_folder, 'covers', book.cover.filename)
    try:
        if os.path.exists(cover_path):
            os.remove(cover_path)
    except Exception as e:
        app.logger.error(f"Ошибка при удалении файла обложки: {e}")

    db.session.delete(book)
    db.session.commit()

    flash(f'Книга "{book.title}" успешно удалена.', 'success')
    return redirect(url_for('index'))

@app.route('/books/<int:book_id>/review/new', methods=['GET', 'POST'])
@login_required
def add_review(book_id):
    book = Book.query.get_or_404(book_id)

    if current_user.role.name not in ('user', 'moderator', 'admin'):
        flash('У вас недостаточно прав для добавления рецензии', 'danger')
        return redirect(url_for('view_book', book_id=book_id))

    existing_review = Review.query.filter_by(book_id=book_id, user_id=current_user.id).first()
    if existing_review:
        flash('Вы уже оставили рецензию на эту книгу', 'warning')
        return redirect(url_for('view_book', book_id=book_id))

    if request.method == 'POST':
        try:
            rating = int(request.form['rating'])
            text_raw = request.form['text']
            allowed_tags = bleach.sanitizer.ALLOWED_TAGS.union({'p', 'br', 'ul', 'ol', 'li', 'strong', 'em', 'a', 'blockquote'})
            text_clean = bleach.clean(text_raw, tags=allowed_tags, strip=True)
            review = Review(
                book_id=book_id,
                user_id=current_user.id,
                rating=rating,
                text=text_clean,
                status='pending'
            )
            db.session.add(review)
            db.session.commit()

            flash('Рецензия успешно добавлена', 'success')
            return redirect(url_for('view_book', book_id=book_id))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при сохранении рецензии. Проверьте корректность введённых данных.', 'danger')

    return render_template('add_review.html', book=book)

@app.route('/reviews/<int:review_id>/delete', methods=['POST'])
@login_required
def delete_review(review_id):
    review = Review.query.get_or_404(review_id)

    if review.user_id != current_user.id and current_user.role.name not in ['admin', 'moderator']:
        flash('У вас недостаточно прав для выполнения данного действия', 'error')
        return redirect(url_for('view_book', book_id=review.book_id))

    try:
        book_id = review.book_id
        db.session.delete(review)
        db.session.commit()
        flash('Рецензия успешно удалена', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Ошибка при удалении рецензии: {str(e)}')
        flash('При удалении рецензии возникла ошибка', 'error')

    return redirect(url_for('view_book', book_id=book_id))

@app.route('/reviews/moderation')
@login_required
@role_required('admin', 'moderator')
def review_moderation():
    reviews = Review.query.filter_by(status='pending').order_by(Review.created_at.desc()).all()
    return render_template('review_moderation.html', reviews=reviews)

@app.route('/reviews/<int:review_id>/approve', methods=['POST'])
@login_required
@role_required('admin', 'moderator')
def approve_review(review_id):
    review = Review.query.get_or_404(review_id)
    review.status = 'approved'
    db.session.commit()
    flash('Рецензия одобрена', 'success')
    return redirect(url_for('review_moderation'))

@app.route('/reviews/<int:review_id>/reject', methods=['POST'])
@login_required
@role_required('admin', 'moderator')
def reject_review(review_id):
    review = Review.query.get_or_404(review_id)
    review.status = 'rejected'
    db.session.commit()
    flash('Рецензия отклонена', 'warning')
    return redirect(url_for('review_moderation'))

@app.route('/admin/statistics')
@login_required
def admin_statistics():
    if current_user.role.name != 'admin':
        abort(403)
    page_log = request.args.get('page_log', 1, type=int)
    page_stats = request.args.get('page_stats', 1, type=int)
    date_from_str = request.args.get('date_from', '')
    date_to_str = request.args.get('date_to', '')
    date_from = None
    date_to = None

    date_format = '%Y-%m-%d'
    try:
        if date_from_str:
            date_from = datetime.strptime(date_from_str, date_format)
        if date_to_str:
            date_to = datetime.strptime(date_to_str, date_format)
            date_to = date_to.replace(hour=23, minute=59, second=59)
    except ValueError:
        pass

    log_query = db.session.query(
        BookView,
        User,
        Book
    ).outerjoin(User, BookView.user_id == User.id) \
     .join(Book, BookView.book_id == Book.id) \
     .order_by(BookView.viewed_at.desc())

    log_pagination = log_query.paginate(page=page_log, per_page=10, error_out=False)

    stats_query = db.session.query(
        Book,
        func.count(BookView.id).label('views_count')
    ).join(BookView).filter(BookView.user_id.isnot(None))

    if date_from:
        stats_query = stats_query.filter(BookView.viewed_at >= date_from)
    if date_to:
        stats_query = stats_query.filter(BookView.viewed_at <= date_to)

    stats_query = stats_query.group_by(Book.id).order_by(desc('views_count'))

    stats_pagination = stats_query.paginate(page=page_stats, per_page=10, error_out=False)

    return render_template('statistics.html',
                           log_pagination=log_pagination,
                           stats_pagination=stats_pagination,
                           date_from=date_from_str,
                           date_to=date_to_str)

@app.route('/admin/statistics/export_csv')
@login_required
def export_csv():
    if current_user.role.name != 'admin':
        abort(403)

    export_type = request.args.get('export_type')
    date_from_str = request.args.get('date_from')
    date_to_str = request.args.get('date_to')

    date_from = None
    date_to = None
    date_format = '%Y-%m-%d'
    try:
        if date_from_str:
            date_from = datetime.strptime(date_from_str, date_format)
        if date_to_str:
            date_to = datetime.strptime(date_to_str, date_format)
            date_to = date_to.replace(hour=23, minute=59, second=59)
    except ValueError:
        pass

    now_str = datetime.utcnow().strftime('%Y-%m-%d')

    output = BytesIO()
    output.write(b'\xef\xbb\xbf')

    text_stream = TextIOWrapper(output, encoding='utf-8', newline='')
    writer = csv.writer(text_stream, delimiter=';', quoting=csv.QUOTE_MINIMAL)

    if export_type == 'user_log':
        writer.writerow(['№', 'ФИО пользователя', 'Название книги', 'Дата и время просмотра'])

        query = db.session.query(BookView, User, Book)\
            .outerjoin(User, BookView.user_id == User.id)\
            .join(Book, BookView.book_id == Book.id)\
            .order_by(BookView.viewed_at.desc())

        all_records = query.all()

        for idx, (view, user, book) in enumerate(all_records, start=1):
            fio = f"{user.last_name} {user.first_name} {user.middle_name or ''}".strip() if user else "Неаутентифицированный пользователь"
            writer.writerow([idx, fio, book.title, view.viewed_at.strftime('%Y-%m-%d %H:%M:%S')])

        filename = f"user_log_{now_str}.csv"

    elif export_type == 'book_stats':
        writer.writerow(['№', 'Название книги', 'Количество просмотров'])

        query = db.session.query(Book, func.count(BookView.id).label('views_count'))\
            .join(BookView)\
            .filter(BookView.user_id.isnot(None))

        if date_from:
            query = query.filter(BookView.viewed_at >= date_from)
        if date_to:
            query = query.filter(BookView.viewed_at <= date_to)

        query = query.group_by(Book.id).order_by(func.count(BookView.id).desc())

        all_stats = query.all()

        for idx, (book, views_count) in enumerate(all_stats, start=1):
            writer.writerow([idx, book.title, views_count])

        filename = f"book_stats_{now_str}.csv"

    else:
        abort(400, "Неизвестный тип экспорта")

    text_stream.flush()
    output.seek(0)

    return Response(
        output.read(),
        mimetype='text/csv',
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "text/csv; charset=utf-8"
        }
    )

if __name__ == '__main__':
    app.run(debug=True)