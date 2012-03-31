# encoding: UTF-8
# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# Note that this schema.rb definition is the authoritative source for your
# database schema. If you need to create the application database on another
# system, you should be using db:schema:load, not running all the migrations
# from scratch. The latter is a flawed and unsustainable approach (the more migrations
# you'll amass, the slower it'll run and the greater likelihood for issues).
#
# It's strongly recommended to check this file into your version control system.

ActiveRecord::Schema.define(:version => 20120328233442) do

  create_table "actions", :force => true do |t|
    t.string  "name"
    t.integer "action"
    t.integer "severity"
    t.integer "retval"
    t.integer "signature_set_id"
    t.integer "available_function_id"
    t.integer "retprotectType"
    t.integer "retprotectMode"
    t.integer "actiontype"
    t.text    "notes"
    t.text  "modblacklist"
    t.text  "modwhitelist"
    t.text  "procblacklist"
    t.text  "procwhitelist"
  end

  create_table "alert_args", :force => true do |t|
    t.binary  "data"
    t.integer "parameter_id"
    t.integer "alert_id"
  end

  add_index "alert_args", ["alert_id"], :name => "index_alert_args_on_alert_id"
  add_index "alert_args", ["parameter_id", "alert_id"], :name => "index_alert_args_on_parameter_id_and_alert_id", :unique => true
  add_index "alert_args", ["parameter_id"], :name => "index_alert_args_on_parameter_id"

  create_table "alerts", :force => true do |t|
    t.integer  "action_id"
    t.datetime "created_at"
    t.datetime "updated_at"
    t.string   "user"
    t.string   "process"
    t.integer  "pid"
    t.string   "computer"
    t.string   "ip"
    t.integer  "count"
    t.string   "module"
  end

  add_index "alerts", ["action_id"], :name => "index_alerts_on_action_id"

  create_table "arguments", :force => true do |t|
    t.integer "argtype"
    t.string  "regExp"
    t.integer "val1"
    t.integer "val2"
    t.integer "parameter_id"
    t.integer "action_id"
  end

  create_table "available_dlls", :force => true do |t|
    t.string "name"
  end

  add_index "available_dlls", ["name"], :name => "index_available_dlls_on_name", :unique => true

  create_table "available_functions", :force => true do |t|
    t.string  "name"
    t.text  "decl"
    t.integer "available_dll_id"
  end

  add_index "available_functions", ["available_dll_id"], :name => "index_available_functions_on_available_dll_id"

  create_table "parameters", :force => true do |t|
    t.string  "name"
    t.integer "paramtype"
    t.integer "num"
    t.integer "size"
    t.integer "arg"
    t.integer "available_function_id"
  end

  add_index "parameters", ["available_function_id", "name"], :name => "index_parameters_on_available_function_id_and_name", :unique => true
  add_index "parameters", ["available_function_id"], :name => "index_parameters_on_available_function_id"

  create_table "signature_sets", :force => true do |t|
    t.float    "version"
    t.string   "report"
    t.integer  "serial"
    t.datetime "created_at"
    t.datetime "updated_at"
    t.string   "name"
    t.string   "procblacklist"
    t.string   "aggregator"
    t.integer  "aggregator_port"
  end

  add_index "signature_sets", ["serial", "version"], :name => "index_signature_sets_on_serial_and_version", :unique => true

  create_table "users", :force => true do |t|
    t.string   "username"
    t.string   "password_hash"
    t.string   "password_salt"
    t.datetime "created_at"
    t.datetime "updated_at"
  end

end
