require "#{File.dirname(__FILE__)}/url_for"

# Copyright (c) 2005 David Heinemeier Hansson
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
module SslRequirement
  mattr_writer :ssl_host, :non_ssl_host, :disable_ssl_check, :redirect_status

  def self.ssl_host
    determine_host(@@ssl_host) rescue nil
  end

  def self.non_ssl_host
    determine_host(@@non_ssl_host) rescue nil
  end

  # mattr_reader would generate both ssl_host and self.ssl_host
  def ssl_host
    SslRequirement.ssl_host
  end

  def non_ssl_host
    SslRequirement.non_ssl_host
  end

  def self.disable_ssl_check?
    @@disable_ssl_check ||= false
  end


  # called when Module is mixed in
  def self.included(controller)
    controller.extend(ClassMethods)
    controller.before_filter(:ensure_proper_protocol)
  end

  module ClassMethods
    # Specifies that the named actions requires an SSL connection to be performed (which is enforced by ensure_proper_protocol).
    def ssl_required(*actions)
      write_inheritable_array(:ssl_required_actions, actions)
    end

    def ssl_exceptions(*actions)
      write_inheritable_array(:ssl_required_except_actions, actions)
    end

    # To allow SSL for any action pass :all as action like this:
    # ssl_allowed :all
    def ssl_allowed(*actions)
      write_inheritable_array(:ssl_allowed_actions, actions)
    end
  end

  protected
  # Returns true if the current action is supposed to run as SSL
  def ssl_required?
    required = (self.class.read_inheritable_attribute(:ssl_required_actions) || [])
    except  = self.class.read_inheritable_attribute(:ssl_required_except_actions)

    unless except
      required.include?(action_name.to_sym)
    else
      !except.include?(action_name.to_sym)
    end
  end

  def ssl_allowed?
    allowed_actions = (self.class.read_inheritable_attribute(:ssl_allowed_actions) || [])

    allowed_actions == [:all] || allowed_actions.include?(action_name.to_sym)
  end

  # normal ports are the ports used when no port is specified by the user to the browser
  # i.e. 80 if the protocol is http, 443 is the protocol is https
  NORMAL_PORTS = [80, 443]

  private
  def ensure_proper_protocol
    return true if SslRequirement.disable_ssl_check?

    if ssl_required? && !request.ssl?
      redirect_to determine_redirect_url(request, true), :status => (redirect_status || 302)
      flash.keep
      return false
    elsif request.ssl? && ssl_allowed?
      return true
    elsif request.ssl? && !ssl_required?
      redirect_to determine_redirect_url(request, false), :status => (redirect_status || 302)
      flash.keep
      return false
    end
  end

  def determine_redirect_url(request, ssl)
    protocol = ssl ? "https" : "http"
    "#{protocol}://#{determine_host_and_port(request, ssl)}#{request.fullpath}"
  end

  def determine_host_and_port(request, ssl)
    request_host = request.host
    request_port = request.port

    if ssl
      "#{(ssl_host || request_host)}#{determine_port_string(request_port)}"
    else
      "#{(non_ssl_host || request_host)}#{determine_port_string(request_port)}"
    end
  end

  def self.determine_host(host)
    if host.is_a?(Proc) || host.respond_to?(:call)
      host.call
    else
      host
    end
  end

  def determine_port_string(port)
    unless port_normal?(port)
      ":#{port}"
    else
      ""
    end
  end

  def port_normal?(port)
    NORMAL_PORTS.include?(port)
  end
end
