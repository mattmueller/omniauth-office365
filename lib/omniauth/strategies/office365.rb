require 'omniauth-oauth2'
require 'jwt'

module OmniAuth
  module Strategies
    # Authentication strategy for connecting with the Office365 API.
    class Office365 < OmniAuth::Strategies::OAuth2
      # Give your strategy a name.
      option :name, 'office365'

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, :site => 'https://graph.microsoft.com',
                              :authorize_url => 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                              :token_url => 'https://login.microsoftonline.com/common/oauth2/v2.0/token'

      def callback_phase # rubocop:disable AbcSize, CyclomaticComplexity, MethodLength, PerceivedComplexity
        error = request.params["error_reason"] || request.params["error"]
        if error
          fail!(error, CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"]))
        elsif !options.provider_ignores_state && (request.params["state"].to_s.empty? || request.params["state"] != session.delete("omniauth.state"))
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
        else
          self.access_token = build_access_token
          self.access_token = access_token.refresh! if access_token.expired?
          env['omniauth.auth'] = auth_hash
          call_app!
        end
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid { raw_info['sub'] }

      # https://github.com/intridea/omniauth/wiki/Auth-Hash-Schema#schema-10-and-later
      info do
        {
          :name => raw_info['name'],
          :email => raw_info['email'],
          :nickname => raw_info['preferred_username']
        }
      end

      extra do
        {
          :raw_info => raw_info
        }
      end

      def raw_info
        @raw_info ||= JWT.decode(access_token.params['id_token'], nil, false, { algorithm: 'RS256' }).first
      end

      protected

      def build_access_token
        verifier = request.params["code"]
        client.auth_code.get_token(verifier, {}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
      end
    end
  end
end
