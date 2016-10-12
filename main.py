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

from string import letters
from google.appengine.ext import db

import webapp2
import jinja2

import logging

import hmac
import random

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                             autoescape = True)

SECRET = 'somethingsecret'


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

logger.info('info')
logger.debug('debug')

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def make_salt():
    return ''.join(random.choice(letters) for i in xrange(5))

# def hash_str(s):
#     return hmac.new(SECRET, s).hexdigest()


def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()

    h = hmac.new(SECRET, name + pw + salt).hexdigest()
    return "%s|%s" % (h, salt)


def valid_pw(name, pw, h):
    if h == make_pw_hash(name, pw, h[1]):
        return True
    else:
        return False

def valid_cookie(cookie):
    if cookie:
        user_data = cookie.split('|', 1)

        logger.info('user_data: %s , %s' % (user_data[0], user_data[1]))
        user = db.GqlQuery("SELECT * FROM User WHERE name = '%s' AND pw_hash ='%s'" % (user_data[0], user_data[1])).get()
         # %s" % (str(user_data[0])))
            # AND pw_hash = %s" % (user_data[0], user_data[1]))
        logger.info('valid cookie() db.GqlQuery : user =%s' % (user.name))

        return True

        # if user:
        #     return True
        # else:
        #     return False
    else:
        return False

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.EmailProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)



class Item(db.Model):
    title = db.StringProperty(required = True)
    text = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)



pw_hash = make_pw_hash('me', 'admin')

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))



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
        self.render('new-post.html')

    def post(self):
        post_title = self.request.get('title')
        post_text = self.request.get('text')

        params = dict(title = post_title, text = post_text)

        if post_title and post_text:
            i = Item(title = post_title, text = post_text)
            i.put()
            self.redirect('/blog')
        else:
            self.render_front(**params)




class Signup(Handler):
    def get(self):
        user_cookie = self.request.cookies.get('user')
        logger.debug("user_cookie=%s" % user_cookie)
        if valid_cookie(user_cookie):
            self.redirect('/blog')
        else:
            self.render('signup.html')

    def post(self):
        self.response.headers['Content-Type'] = 'text/plain'

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
            user_params = {}
            user_params['name'] = username
            user_params['pw_hash'] = make_pw_hash(username, password)
            if email:
                user_params['email'] = email
            u = User(**user_params)
            u.put()
            self.response.headers.add_header('Set-Cookie', 'user=%s|%s' % (str(username), user_params['pw_hash']))
            self.redirect('/shopping_list')

class Blog(Handler):
    def get(self):
        items = db.GqlQuery("SELECT * FROM Item ORDER BY created DESC")
        self.render('blog.html', items = items)
        logger.debug("another bug test")

class Login(Handler):
    def get(self):
        self.render('login.html')


class Welcome(Handler):
    def get(self):
        user_cookie = self.request.cookies.get('user')
        if user_cookie:
            self.render('shopping_list.html', user = user_cookie.split('|')[0])
        else:
            self.render('shopping_list.html', user = 'unknown')
        # user_cookie = self.request.cookies.get('user')
        # if user_cookie:
        #     self.render('shopping_list.html', user = user_cookie)
        # else:
        # self.redirect('/signup')

    def post(self):
        user_cookie = self.request.cookies.get('user')
        if user_cookie:
            self.render('shopping_list.html', user = user_cookie)
        else:
            self.redirect('/signup')

    	
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Signup), 
    ('/shopping_list', Welcome),
    ('/new-post', MakeBlogPost),
    ('/blog', Blog),
    ('/login', Login)
], debug=True)
