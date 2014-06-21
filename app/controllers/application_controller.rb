class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  if Rails.application.secrets.enable_authentication
    http_basic_authenticate_with(
      name: Rails.application.secrets.username,
      password: Rails.application.secrets.password
    )
  end

  def boot
  end
end
