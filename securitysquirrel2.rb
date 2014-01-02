# Securitysquirrel proof of concept by rmogull@securosis.com
# This is a simple demonstration that evaluates your EC2 environment and identifies instances not managed with Chef.
# It demonstrates rudimentary security automation by gluing together AWS and Chef using APIs.

# You must install the gems aws-sdk and ridley. Ridley is a Ruby gem for direct Chef API access.

require "rubygems"
require "aws-sdk"
require "ridley"
require "json"

class ConfigManagement
  def analyze
    # Load configuration and credentials from a JSON file

    configfile = File.read('creds.json')
    config = JSON.parse(configfile)
    
    # set AWS config

    AWS.config(access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: 'us-west-2')


    # Fill the ec2 class
    ec2 = AWS.ec2 #=> AWS::EC2
    ec2.client #=> AWS::EC2::Client
   
    # Memoize is an AWS function to speed up collecting data by keeping the hash in local cache. This line creates a list of the EC2 private DNS names, which we will use to identify nodes in Chef.
      instancelist = AWS.memoize { ec2.instances.map(&:private_dns_name) }

      # some code below I'm playing with
      # temp = ec2.instances.inject({}) { |m, i| m[i.id] = i.private_dns_name; m }
      # puts temp
      # ec2.instances.each do |instance|
      #   puts instance.id
      # end

      # Start a ridley connection to our Chef server. Pull the configuration from our file.

      chefconfig = config["chef"]

      ridley = Ridley.new(
        server_url: "#{config["chef"]["chefserver"]}",
        client_name: "#{config["chef"]["clientname"]}",
        client_key: "#{config["chef"]["keylocation"]}",
        ssl: { verify: false }
        )

        # Ridley has a bug, so we need to work on the node name, which in our case is the same as the EC2 private DNS. For some reason the node.all doesn't pull IP addresses (it's supposed to) which is what we would prefer to use.
        nodes = ridley.node.all
        nodenames = nodes.map { |node| node.name }

        # For every EC2 instance, see if there is a corresponding Chef node.

        puts ""
        puts ""
        puts "Instance            =>                      managed?"
        puts ""
        instancelist.each do |thisinstance|
          managed = nodenames.include?(thisinstance)
          puts " #{thisinstance} #{managed} "
        end
  end
end







managed_test = ConfigManagement.new
managed_test.analyze