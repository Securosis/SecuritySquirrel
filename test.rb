require "rubygems"
require "aws-sdk"
require "ridley"
require "json"

# Since this is a PoC I hard-coded the credentials. Fill in your own, or adjust the program to use a config file or environment variables. Don't forget to select the region..

# AWS.config(access_key_id: 'AKIAI27NYUSFJGXK3KFA', secret_access_key: 'HJfvNdvfjiZbRUfBv9kzBR8UdrIBt5IbDJ6Ti+bP', region: 'us-west-2')

# Load credentials from a JSON file

config = File.read('creds.json')
credentials = JSON.parse(config)
awscreds = credentials["aws"]
puts credentials["aws"]["AccessKey"]