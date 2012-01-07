class Alert < ActiveRecord::Base
  belongs_to :action
  has_many :alert_args, :dependent => :destroy
end
