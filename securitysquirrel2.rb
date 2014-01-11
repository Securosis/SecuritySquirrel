# Securitysquirrel proof of concept by rmogull@securosis.com
# This is a simple demonstration that evaluates your EC2 environment and identifies instances not managed with Chef.
# It demonstrates rudimentary security automation by gluing together AWS and Chef using APIs.

# You must install the gems aws-sdk and ridley. Ridley is a Ruby gem for direct Chef API access.

require "rubygems"
require "aws-sdk"
require 'aws-sdk-core'
require "ridley"
require "json"

# class for chef integration
class ConfigManagement
  # This class integrates with Chef for configuration management. Right now it only has one method. Need to move initialization to an init method when I add more functionality. 
  def analyze
    # This method polls EC2 and polls Chef to identify any unmanaged instances.
    # Right now it uses the instance name since there is a bug in the Ridley SDK that limits pulling alternate attribures, but plan is to fix that soon
    
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
      
      #supress errors since Ridley is buggy; switch to "fatal" if it keeps showing up.
      Ridley::Logging.logger.level = Logger.const_get 'ERROR'
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

#class for incident resposne functions like quarantine.
class IncidentResponse
  def initialize(instance_id)
    @instance_id = instance_id
    
    # Load configuration and credentials from a JSON file
    configfile = File.read('config.json')
    config = JSON.parse(configfile)
    
    # Set AWS config
    AWS.config(access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: 'us-west-2')
    
    # Set application configuration variables
    @@QuarantineGroup = "#{config["aws"]["QuarantineSecurityGroup"]}"

    # Fill the ec2 class
    @@ec2 = AWS.ec2 #=> AWS::EC2
    @@ec2.client #=> AWS::EC2::Client
    
    # Added code for the AWS SDK version 2.0 (aws-sdk-core) that has more functions, but kills some existing code so not fully converting to it yet.
    
    Aws.config = { access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: 'us-west-2' }
    
    @@ec22 = Aws::EC2.new
    @@ec22 = Aws.ec2
  end
  
  def quarantine
    # this method moves the provided instance into the Quarantine security group defined in the config file.
    puts ""
    puts "Quarantining #{@instance_id}..."
   quarantine = @@ec22.modify_instance_attribute(instance_id: "#{@instance_id}", groups: ["#{@@QuarantineGroup}"])
   puts "#{@instance_id} moved to the Quarantine security group from your configuration settings."
   end
  
  def tag
    # this method adds an "status => IR" tag to the instance.
    # If you properly configure your IAM policies, this will move ownership fo the instance to the security
    # team and isolate it so no one else can terminate/stop/modify/etc.
    puts "Tagging instance with 'IR'..."
    tag = @@ec22.create_tags(resources: ["#{@instance_id}"], tags: [
    {
      key: "SecurityStatus",
      value: "IR",
    },
  ],)
  puts "Instance tagged and IAM restrictions applied."
  end
  
  def snapshot
    # This method determines the volume IDs for the instance, then creates snapshots of those def volumes(args)
    # Get the instance details for the instance
    instance_details = @@ec22.describe_instances(
      instance_ids: ["#{@instance_id}"],
    )
    # find the attached block devices, then the ebs volumes, then the volume ID for each EBS volume. This involves walking the response tree.
    # There is probably a better way to do this in Ruby, but I'm still learning.
    puts "Identifying attached volumes..."
    block_devices = instance_details.reservations.first.instances.first.block_device_mappings
    ebs = block_devices.map(&:ebs)
    volumes = ebs.map(&:volume_id)
    volumes.each do |vol|
      puts "Volume #{vol} identified; creating snapshot"
      # Create a snapshot of each volume and add the volume and instance ID to the description.
      # We do this since you can't apply a name tag until the snapshot is created, and we don't want to slow down the process.
      snap = @@ec22.create_snapshot(
        volume_id: "#{vol}",
        description: "IR volume #{vol} of instance #{@instance_id}",
      )
      puts "Snapshot complete with description: IR volume #{vol} of instance #{@instance_id} "
    end
    
  end
  
  
end
    
    

# Body code, currently in a test state
#Run basic analysis
puts "\e[H\e[2J"
puts "Welcome to SecuritySquirrel. Please select an action:"
puts ""
puts "1. Identify all unmanaged instances"
puts "2. Initiate Full Quarantine and Forensics on an instance"
puts ""
print "Select: "
menuselect = gets.chomp
if menuselect == "1"
  managed_test = ConfigManagement.new
  managed_test.analyze
elsif menuselect == "2"
  puts "\e[H\e[2J"
  print "Enter Instance ID:"
  instance_id = gets.chomp
  incident_response = IncidentResponse.new(instance_id)
  incident_response.quarantine
  puts ""
  incident_response.tag
  puts ""
  incident_response.snapshot
  puts ""
  
end

