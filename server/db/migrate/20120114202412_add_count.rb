class AddCount < ActiveRecord::Migration
  def change
    change_table :alerts do |t|
      t.integer :count
    end
  end
end
