require 'omniauth/core'

module OmniAuth
  class Builder < ::Rack::Builder
    def on_failure(&block)
      OmniAuth.config.on_failure = block
    end

    def configure(&block)
      OmniAuth.configure(&block)
    end

    def provider(klass, *args, &block)
      if klass.is_a?(Class)
        middleware = klass
      else
        middleware = OmniAuth::Strategies.const_get("#{OmniAuth::Utils.camelize(klass.to_s)}")
      end

      use middleware, *args, &block
    end

    def call(env)
      to_app.call(env)
    end
  end
end
