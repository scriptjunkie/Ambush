class AddModule < ActiveRecord::Migration
  def change
    change_table :actions do |t|
      t.string :module
    end
  end
end
