require 'omniauth/core'
require 'rbox'

module OmniAuth
  module Strategies
    class Box
      include OmniAuth::Strategy

      # Initialize the strategy by providing
      #
      # @param api_token
      # @param options
      def initialize(app, api_token, options = {})
        super(app, :box)
        @api_token = api_token
        @client = ::Rbox.new({ :api_token => api_token })
      end

      protected


      def request_phase
        @client.get_ticket
        redirect @client.authorize_url
      end

      def callback_phase
        @auth_token = request.params['auth_token']
        @client.auth_token = @auth_token
        @account_info = @client.get_account_info

        raise 'Failed authentication' unless @account_info.success?
        super
      end

      def auth_hash
        {
          'uid' => @account_info.user['user_id'],
          'credentials' => { 'token' => @auth_token },
          'user_info' => @account_info.attributes,
          'extra' => { 'user_hash' => @account_info.attributes }
        }
      end
      
      def user_info
        {
          'email' => @account_info.user['email'],
          'nickname' => @account_info.user['login']
        }
      end
    end
  end
end
