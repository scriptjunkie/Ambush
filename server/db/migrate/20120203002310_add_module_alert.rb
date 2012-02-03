class AddModuleAlert < ActiveRecord::Migration
  def change
    change_table :alerts do |t|
      t.string :module
    end
  end
end
