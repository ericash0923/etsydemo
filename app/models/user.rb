class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  validates :name, presence: true
  
  ##dependent: :destroy => if the users is deleted, then the listing will auto be deleted as well
  has_many :listings, dependent: :destroy
end
