class ApplicationController < ActionController::Base
  protect_from_forgery
  helper_method :current_user

  private

  def current_user
    begin
      @current_user ||= User.find(session[:user_id]) if session[:user_id]
    rescue
      nil
    end
  end

  # call this as a before_filter to require them to be logged in
  def login_required
    if current_user.nil?
      redirect_to login_url, :alert => "You must first log in or sign up before accessing this page."
    end
  end
end
