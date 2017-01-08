import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'developer'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Basic handler for blog
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class HomePage(BlogHandler):
    def get(self):
        self.render('index.html')

# create salt with random letter for password hash
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# create password hash to be stored in db
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# validates password of user using the password hash stored in db
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# create ancestor key for users in the db
def users_key(group='default'):
    return db.Key.from_path('users', group)

# create User model with functions
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# create ancestor key for entire blog model in the db
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# create Post model with function for rendering posts
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.StringProperty()
    likes = db.IntegerProperty()
    unlikes = db.IntegerProperty()
    rated_by = db.ListProperty(str)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

# create Comment model with function for rendering comments
class Comment(db.Model):
    content = db.TextProperty(required=True)
    post = db.ReferenceProperty(Post)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c=self)

# handler for showing the front of the blog wtth last 10 posts
class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        self.render('front.html', posts=posts)

# handler for displaying individual posts with comments
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        params = dict(post=post)

        if Comment.all():
            comments = Comment.all().filter('post =', key)
            params['comments'] = comments

        if self.user:
            params['username'] = self.user.name

        if not post:
            self.error(404)
            return

        self.render("permalink.html", **params)

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        comment_content = self.request.get('content')

        if comment_content:
            post_key = self.request.get('post_key')
            post = Post.get(post_key)
            user = self.user.name

            c = Comment(content=comment_content, post=post, user=user)
            c.put()
            self.redirect('/blog/%s' % post_id)

# handler for adding new post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/blog")
            return

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        user = self.user.name

        if subject and content:
            p = Post(parent=blog_key(),
                     subject=subject,
                     content=content,
                     user=user, likes=0,
                     unlikes=0,
                     rated_by=[])
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)

# handler for editing user posts
class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post and self.user and (self.user.name == post.user):
            self.render("editpost.html",
                        subject=post.subject,
                        content=post.content)
        else:
            self.redirect("/blog")
            return

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post and self.user:
            post.subject = self.request.get('subject')
            post.content = self.request.get('content')
            poster = post.user
            user = self.user.name

        input = self.request.get('submit')

        if user != poster:
            msg = "You can only edit your own posts!"
            self.render("editpost.html", subject=post.subject,
                        content=post.content, error=msg)
            if input == 'Cancel':
                self.redirect('/blog/%s' % post_id)
        else:
            if input == 'Submit':
                if post.subject and post.content:
                    post.put()
                    self.redirect('/blog/%s' % post_id)
            else:
                self.redirect('/blog/%s' % post_id)

# handler for deleting user posts
class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post and self.user and (self.user.name == post.user):
            self.render("deletepost.html",
                        subject=post.subject,
                        content=post.content)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post and self.user:
            poster = post.user
            user = self.user.name

        input = self.request.get('submit')

        if user != poster:
            msg = "You can only delete your own posts!"
            self.render("editpost.html",
                        subject=post.subject,
                        content=post.content,
                        error=msg)
            if input == 'Cancel':
                self.redirect('/blog/%s' % post_id)
        else:
            if input == 'Delete':
                post.delete()
                self.render('front.html')
            else:
                self.redirect('/blog/%s' % post_id)

# # handler for liking user posts
class LikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        poster = post.user
        user = self.user.name
        params = dict(post=post)
        if poster == user:
            params['like_error'] = "You cannot like your own post!"
            self.render('permalink.html', **params)
        else:
            if user in post.rated_by:
                params['like_count_error'] = "You can only vote on a post once!"
                self.render('permalink.html', **params)
            else:
                post.rated_by.append(user)
                post.likes += 1
                post.put()
                self.redirect('/blog/%s' % post_id)

# handler for disliking user posts
class UnlikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        poster = post.user
        user = self.user.name
        params = dict(post=post)
        if poster == user:
            params['like_error'] = "You cannot like your own post!"
            self.render('permalink.html', **params)
        else:
            if user in post.rated_by:
                params['like_count_error'] = "You can only vote on a post once!"
                self.render('permalink.html', **params)
            else:
                post.rated_by.append(user)
                post.unlikes += 1
                post.put()
                self.redirect('/blog/%s' % post_id)

# handler for editing comments
class EditComment(BlogHandler):
    def get(self, comment_id):
        self.response.headers.add_header('Set-Cookie', 'referer=%s; Path=/' % self.request.referer)
        comment = Comment.get_by_id(int(comment_id))
        self.render('editcomment.html', content=comment.content)

    def post(self, comment_id):
        referer = str(self.request.cookies.get('referer'))
        comment = Comment.get_by_id(int(comment_id))
        comment.content = self.request.get('content')
        user = self.user.name
        commenter = comment.user
        input = self.request.get('submit')
        if commenter != user:
            msg = 'You can only edit your own comments!'
            self.render('editcomment.html', content=comment.content, error=msg)
            if input == 'Cancel':
                self.redirect(referer)
        else:
            if input == 'Submit':
                if comment.content:
                    comment.put()
                    self.redirect(referer)
            else:
                self.redirect(referer)

# handler for deleting comments
class DeleteComment(BlogHandler):
    def get(self, comment_id):
        self.response.headers.add_header('Set-Cookie', 'referer=%s; Path=/' % self.request.referer)
        comment = Comment.get_by_id(int(comment_id))
        self.render('deletecomment.html', content=comment.content)

    def post(self, comment_id):
        referer = str(self.request.cookies.get('referer'))
        comment = Comment.get_by_id(int(comment_id))
        comment.content = self.request.get('content')
        user = self.user.name
        commenter = comment.user
        input = self.request.get('submit')
        if commenter != user:
            msg = 'You can only delete your own comments!'
            self.render('deletecomment.html',
                        content=comment.content,
                        error=msg)
            if input == 'Cancel':
                self.redirect(referer)
        else:
            if input == 'Delete':
                comment.delete()
                self.redirect(referer)
            else:
                self.redirect(referer)

# functions to validate username, password and email using regex
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# handler for signing up for the blog
# verfifies valid username, password and email (if available)
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

# handler for registering for the blog
# adds valid user into database
class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

# handler for logging users in and validating login requestts
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)

# handler for logging users out
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

# handler for welcoming authenticated new users
class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', HomePage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)/edit', EditPost),
                               ('/blog/([0-9]+)/delete', DeletePost),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/blog/([0-9]+)/unlike', UnlikePost),
                               ('/blog/([0-9]+)/editcomment', EditComment),
                               ('/blog/([0-9]+)/deletecomment', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
