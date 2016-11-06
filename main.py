# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import re

from google.appengine.api import memcache

from string import letters
from google.appengine.ext import db

import webapp2
import jinja2

import logging
import datetime

import hmac
import random

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                             autoescape = True)

SECRET = 'somethingsecret'

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def make_salt():
    return ''.join(random.choice(letters) for i in xrange(5))


def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()

    h = hmac.new(SECRET, name + pw + salt).hexdigest()
    return "%s|%s" % (h, salt)


def valid_cookie(cookie):
    if cookie:
        user_data = cookie.split('|', 1)
        user = db.GqlQuery("SELECT * FROM User WHERE name = '%s' AND pw_hash ='%s'" % (user_data[0], user_data[1])).get()
        return True

    else:
        return False


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def validPwHash(user, pw):
    hash = memcache.get(key = user)

    if hash is None:
        user_data = db.GqlQuery("SELECT * FROM User WHERE name = '%s'" % (user), read_policy=db.STRONG_CONSISTENCY).get()
        # Question : Correct syntax regarding the "read_policy=db.STRONG_CONSISTENCY" part ?

        if user_data:
            hash = user_data.pw_hash
            salt = user_data.pw_hash.split('|')[1]
            if hash == make_pw_hash(user, pw, salt):
                if not memcache.add(key = user, value = hash):
                    logging.debug('Memcache add failed.')
                return hash
    else:
        salt = hash.split('|')[1]
        if hash == make_pw_hash(user, pw, salt):
            return hash

    return False


    if userData  is not None:
        salt = userData.pw_hash.split('|', 1)[1]

        if userData.pw_hash == make_pw_hash(user, pw, salt):
            return userData.pw_hash

    return False

def loggedInUser(cookie):
    user = None

    logging.info('-------------------- cookie : %s' % cookie)

    # cookie = self.request.cookies.get('user')
    if cookie:
        user_data = cookie.split('|', 1)

    hash = memcache.get(user_data[0])

    if hash is None:
        user = db.GqlQuery("SELECT * FROM User WHERE name = '%s' AND pw_hash ='%s'" % (user_data[0], user_data[1]), read_policy=db.STRONG_CONSISTENCY).get()
        if user:
            hash = user.pw_hash
            if not memcache.add(key = user.name, value = user.pw_hash):
                logging.error('Memcache add failed.')

    if user_data[1] == hash:
        return user_data[0]
    else:
        return None


class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.EmailProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)



class Item(db.Model):
    title = db.StringProperty(required = True)
    text = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    creator = db.StringProperty(required = True)

    def render(self):
        self._render_text = self.text.replace('\n', '<br>')
        return render_str('post.html', p = self)



# pw_hash = make_pw_hash('me', 'admin')

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def loggedInUser(self):
        cookie = self.request.cookies.get('user')
        logging.info('loggedInUser() cookie = %s' % cookie)
        if cookie:
            user_data = cookie.split('|', 1)

            logger.info('user_data: %s , %s' % (user_data[0], user_data[1]))
            user = db.GqlQuery("SELECT * FROM User WHERE name = '%s' AND pw_hash ='%s'" % (user_data[0], user_data[1]), read_policy=db.STRONG_CONSISTENCY).get()
            if user:
                logger.info('valid cookie() db.GqlQuery : user =%s' % (user.name))
                
                return user_data[0]

            # If no cookie or no match in user DB then return False
            else:
                logging.info('FAILED! loggedInUser(): user =%s' % user)
                return False




class MainPage(Handler):
    def get(self):
        # items = self.request.get_all('food')
        items = db.GqlQuery("SELECT * FROM Item ORDER BY created DESC")
        self.render('signup.html', items = items)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)




class MakeBlogPost(Handler):
    def render_front(self, title = "", text = ""):
        self.render('new-post.html', title = title, text = text)

    def get(self):
        user = self.loggedInUser()
        if user:
            self.render('new-post.html', user = user)
        else:
            self.redirect('/blog')



    def post(self):
        user = self.loggedInUser()
        if user:
            self.render('new-post.html', user = user)
        else:
            self.redirect('/blog')
     

        post_title = self.request.get('title')
        post_text = self.request.get('text')

        
        params = dict(title = post_title, text = post_text)

        if post_title and post_text:
            i = Item(parent = blog_key(), title = post_title, text = post_text, creator = user)
            i.put()
            self.redirect('/blog/%s' % str(i.key().id()))
        else:
            self.render_front(**params)

class EditPost(Handler):
    def render_front(self, title = "", text = ""):
        self.render('edit-post.html', title = title, text = text)

    def post(self):
        user = self.loggedInUser()
        logging.info('EditPost()')

        if user:
            self.render('edit-post.html', user = user)
        else:
            self.redirect('/blog')


        post_title = self.request.get('title')
        post_text = self.request.get('text')

        params = dict(title = post_title, text = post_text)

        if post_title and post_text:
            key = db.Key.from_path('Item', int(post_id), parent=blog_key())
            post = db.get(key)
            post.title = post_title
            post.text = post_text
            post.put()

            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            self.render_front(**params)

        

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Item', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)



class Signup(Handler):
    def get(self):
        # user_cookie = self.request.cookies.get('user')
        # logger.debug("nonvalid user_cookie=%s" % user_cookie)

        if self.loggedInUser():
            self.redirect('/blog')
        else:
            self.render('signup.html')

    def post(self):
        # self.response.headers['Content-Type'] = 'text/plain'

        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username, email = email)

        if not valid_username(username):
            params['error_username'] = 'Not valid username.'
            have_error = True

        if not valid_password(password):
            params['error_password'] = 'Not valid password.'
            have_error = True

        elif password != verify:
            params['error_verify'] = 'Your passwords did not match.'
            have_error = True

        if not valid_email(email):
            params['error_email'] = 'That is not a valid email.'
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            isUserInDB = db.GqlQuery("SELECT * FROM User WHERE name = '%s'" % username).get()
            if isUserInDB:
                params['error_username'] = 'Username not available.'
                self.render('signup.html', **params)

            else:
                user_params = {}
                user_params['name'] = username
                user_params['pw_hash'] = make_pw_hash(username, password)
                if email:
                    user_params['email'] = email
                

                u = User(**user_params)
                u.put()
                self.response.headers.add_header('Set-Cookie', 'user=%s|%s' % (str(username), user_params['pw_hash']))
                memcache.add( key = username, value = user_params['pw_hash'])
                self.redirect('/welcome')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')

        params = dict(username = username)

        if not valid_username(username):
            params['error_username'] = 'Not valid username.'
            have_error = True
            # logging.info('login have_error username =%s' % username)


        if not valid_password(password):
            params['error_password'] = 'Not valid password.'
            have_error = True
            # logging.info('login have_error password =%s' % password)


        logging.info('login have_error =%s' % have_error)

        if not have_error:
            pw_hash = validPwHash(username, password)
            logging.info('pw_hash=%s' % (pw_hash))
            if  pw_hash:
                # pw_hash = make_pw_hash(username, password)
                self.response.headers.add_header('Set-Cookie', 'user=%s|%s' % (str(username), (str(pw_hash))))
                memcache.add(key='current_user', value=username, time=3600)
                self.redirect('/blog')
            else:
                params['error_username'] = 'Not valid username and/or password.'
        
        self.render('/login.html', **params)
            

class Welcome(Handler):
    def get(self):
        self.render('welcome.html')


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user=')
        self.redirect('/blog')


class Blog(Handler):
    def get(self):
        logging.info('blog GET')
        current_user = None

        # if current_user:
        #     logging.info('user %s logged in' % current_user)
        # else:
        #     logging.info('no user user is logged in')

        # if not current_user:


        cookie = self.request.cookies.get('user')
        if cookie:
            current_user = loggedInUser(cookie) # None if no user is logged in.

                
        items = db.GqlQuery("SELECT * FROM Item ORDER BY created DESC")
        params = dict(items = items)
        # params['commentable'] = 'commentable'
        # logging.info('---------------  %s' % items[0].key().id())

        timeMessages = []

        a = 0

        for item in items:
            timeMessages.append('secondd try: %s' % str(a))
            a = a+1

        params['timeMessages'] = timeMessages
        # for item in items:
        #     logging.info(item.ID)

        if current_user is not None:
            params['user'] = current_user

        self.render('blog.html', **params)


    def post(self):
        logging.info('****************************************************** blog POST')
        user = self.loggedInUser()
        logging.info('user editing : %s' % user)
        if user:
            # self.render('blog.html', user = user)
            edit_postID = self.request.get('edit_postID')
            editButton = self.request.get('editButton')
            logging.info('editButton = %s' % editButton)
            item = db.get(edit_postID)
            logging.info('edit postID : %s' % edit_postID)
            logging.info('edit item.text : %s' % item.text)
            params = dict(item = item, user = user)
            self.render('edit-post.html', **params)
        else:
            self.redirect('/signup')

    	
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Signup), 
    ('/new-post', MakeBlogPost),
    ('/edit-post', EditPost),
    ('/blog', Blog),
    ('/login', Login),
    ('/welcome', Welcome),
    ('/blog/([0-9]+)', PostPage),
    ('/logout', Logout)
], debug=True)
