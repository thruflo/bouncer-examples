"""`Pyramid`_ web application that uses `Bouncer`_ as its authentication system.
  
  If necessary, install the dependencies with::
  
      pip install pyramid
      pip install requests
  
  Provide `BOUNCER_CLIENT_ID` AND `BOUNCER_CLIENT_SECRET` as environment
  variables and then run with `python pyramid_demo.py`, e.g.::
  
      export BOUNCER_CLIENT_ID=<client_id> BOUNCER_CLIENT_SECRET=<client_secret>
      python pyramid_demo.py
  
  Note that in order for this demo to work, your application should either not
  register a callback URL, or should register the exact callback URL, which
  if run using the command above will be ``http://localhost:6543/auth/callback``.
  
  _`Pyramid`: http://pyramid.readthedocs.org/en/latest/narr/introduction.html
  _`Bouncer`: https://www.bouncer.io
"""

import os
from urllib import urlencode

import requests
from requests.auth import AuthBase

from pyramid.config import Configurator
from pyramid.httpexceptions import HTTPFound
from pyramid.response import Response

AUTHORIZE_ENDPOINT = 'https://www.bouncer.io/oauth/authorize'
TOKEN_ENDPOINT = 'https://www.bouncer.io/oauth/token'
USER_ENDPOINT = 'https://www.bouncer.io/api/user'

class BearerAuth(AuthBase):
    """Attaches HTTP Bearer Authentication to the given Request object."""
    
    def __init__(self, access_token):
        self.access_token = access_token
    
    def __call__(self, request):
        request.headers['Authorization'] = 'Bearer {0}'.format(self.access_token)
        return request
    


def index_view(request):
    """Render a link to log the user in using Bouncer."""
    
    # Generate the login URL, with the right client id and callback URL.  You
    # could also add a `state` parameter for CSRF protection.
    settings = request.registry.settings
    params = {
        'client_id': settings.get('client_id'),
        'redirect_uri': request.route_url('callback'),
        'response_type': 'code'
    }
    login_url = '{0}?{1}'.format(AUTHORIZE_ENDPOINT, urlencode(params))
    
    # Render a hyperlink.
    markup = u"""
      <h1>Sign In</h1>
      <p><a href="{0}">Sign in with Bouncer</a>.</p>
    """
    return Response(markup.format(login_url))

def callback_view(request):
    """Handle the authorization response:
      
      * use the code to get a token
      * use the token to get the user data
      * redirect to the user view
    """
    
    # Handle errors, e.g.: with a try again link...
    error = request.params.get('error')
    if error:
        markup = u"""
          <h1>Whoops!</h1>
          <p><a href="/">Try that again</a></p>.
          <pre>{0}</pre>
        """
        return Response(markup.format(request.params))
    
    # Otherwise we will have an authorization code.  N.b.: You might want to
    # validate and check the `state` param here...
    code = request.params.get('code')
    
    # Use the authorization code to get an access token.
    settings = request.registry.settings
    params = {
        'code': code,
        'grant_type': 'authorization_code', 
        'redirect_uri': request.route_url('callback')
    }
    auth = (settings.get('client_id'), settings.get('client_secret'))
    response = requests.get(TOKEN_ENDPOINT, params=params, auth=auth)
    token_data = response.json
    
    # Use the token to get the user's data.
    auth = BearerAuth(token_data['access_token'])
    response = requests.get(USER_ENDPOINT, auth=auth)
    user_data = response.json.get('data')
    
    # At this point you might log the user in, save the data, etc.  We'll just
    # redirect to /user/:username.
    username = user_data.get('username')
    url = request.route_url('user', username=username)
    return HTTPFound(location=location)

def user_view(request):
    """Render a simple user view."""
    
    # Unpack the request.
    username = request.matchdict.get('username')
    
    # Render the user data.
    markup = u"""
      <h1>Welcome {0}!</h1>
      <p><a href="/">Go again</a></p>.
    """
    return Response(markup.format(username))


def app_factory():
    """Create a Pyramid app using the OS environment variable settings."""
    
    # Parse the client credentials from the OS environment.
    client_id = os.environ.get('BOUNCER_CLIENT_ID')
    client_secret = os.environ.get('BOUNCER_CLIENT_SECRET')
    
    # Configure an application with the settings provided.
    settings = dict(client_id=client_id, client_secret=client_secret)
    config = Configurator(settings=settings)
    # Exposeing three views:
    # - index renders a link to Bouncer's /oauth/authorize endpoint.
    # - callback handles the /oauth/authorize's redirect response.
    # - user displays the "logged in" user.
    config.add_route('index', '/')
    config.add_route('callback', 'auth/callback')
    config.add_route('user', 'user/:username')
    config.add_view(index_view, route_name='index')
    config.add_view(callback_view, route_name='callback')
    config.add_view(user_view, route_name='user')
    return config.make_wsgi_app()

def serve(wsgi_app):
    """Run the Pyramid ``app`` using a simple WSGI server."""
    
    from wsgiref.simple_server import make_server
    server = make_server('0.0.0.0', 6543, wsgi_app)
    server.serve_forever()


if __name__ == '__main__':
    print 'Serving on http://localhost:6543'
    try:
        serve(app_factory())
    except KeyboardInterrupt:
        pass

