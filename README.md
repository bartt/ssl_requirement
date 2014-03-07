Installing
==========

This version of SSL Requirement is **only** compatible with Rails 3.x.  To install add the following line to your project's
`Gemfile`:

    gem 'bartt-ssl_requirement', '~>1.4.0', :require => 'ssl_requirement'

`bartt-ssl_requirement` is compatible with ruby 1.8.7 and 1.9.x.

SSL Requirement
===============

SSL requirement adds a declarative way of specifying that certain actions
should only be allowed to run under SSL, and if they're accessed without it,
they should be redirected.

Example:

    class ApplicationController < ActionController::Base
      include ::SslRequirement
    end

    class AccountController < ApplicationController
      ssl_required :signup, :payment
      ssl_allowed :index

      def signup
        # Non-SSL access will be redirected to SSL
      end

      def payment
        # Non-SSL access will be redirected to SSL
      end

      def index
        # This action will work either with or without SSL
      end

      def other
        # SSL access will be redirected to non-SSL
      end
    end

If a majority (or all) of your actions require SSL, then use `ssl_exceptions` instead of `ssl_required`.
You can list out the actions that you do NOT want to be SSL protected. Calling `ssl_exceptions` without
any actions listed will make ALL actions SSL protected.

To allow or require SSL for all actions, pass `:all` to their respective methods.

Example:

   # This will enable SSL for all actions in your application.
   class ApplicationController < ActionController::Base
      include ::SslRequirement

      ssl_allowed :all
    end

You can overwrite the protected method `ssl_required?` to rely on other things
than just the declarative specification. Say, only premium accounts get SSL.

For SSL domains that differ from the domain of the redirecting site, add the
following code to `development.rb` / `test.rb` / `production.rb`:

    # Redirects to https://secure.example.com instead of the default
    # https://www.example.com.
    config.after_initialize do
      SslRequirement.ssl_host = 'secure.example.com'
    end

For non-SSL domains that differ from domain of redirecting site, add the
following code to `development.rb` / `test.rb` / `production.rb`:

  # Redirects to http://nonsecure.example.com instead of the default
  # http://www.example.com.
  config.after_initialize do
    SslRequirement.non_ssl_host = 'nonsecure.example.com'
  end

You can also use a Proc to determine the `ssl_host` or `non_ssl_host` on the fly:

  config.after_initialize do
      SslRequirement.ssl_host = Proc.new do
    'secure.example.com'
    end
    end

You are able to turn off ssl redirects by adding the following environment configuration file:

    SslRequirement.disable_ssl_check = true

You are able to the change the status code (defaults to 302) of the redirect by
addng the following to the environment configuration file:

  SslRequirement.redirect_status = :moved_permanently

P.S.: Beware when you include the `SslRequirement` module. At the time of
inclusion, it'll add the `before_filter` that validates the declarations. Some
times you'll want to run other `before_filter`s before that. They should then be
declared ahead of including this module.

SSL URL Helper
==============
This plugin also adds a helper a `:secure` option to `url_for` and `named_routes`. This property
allows you to set a url as secure or not secure. It uses the `disable_ssl_check` to determine
if the option should be ignored or not so you can develop as normal. It also
will obey if you override `SslRequirement.ssl_host` or
`SslRequirement.non_ssl_host` (see above)

Here is an example of creating a secure url:

    <%= url_for(:controller => "c", :action => "a", :secure => true) %>

If `disable_ssl_check` returns false `url_for` will return the following:

    https://yoursite.com/c/a

Furthermore, you can use the secure option in a named route to create a secure form as follows:

    <% form_tag session_path(:secure => true), :class => 'home_login' do -%>
      <p>
        <label for="name">Email</label>
        <%= text_field_tag 'email', '', :class => 'text', :tabindex => 1 %>
      </p>
      <p>
        <label for="password">Password</label>
        <%= password_field_tag 'password', '', :class => 'text', :tabindex => 2 %>
      </p>
      <p>
        <%= submit_tag "Login", :id => 'login_submit', :value => "", :alt => "Login" %>
      </p>
    <% end -%>

Copyright
=========

Copyright (c) 2005 David Heinemeier Hansson, released under the MIT license
