# Securitysquirrel proof of concept by rmogull@securosis.com
# Copyright 2014 Rich Mogull and Securosis, LLC. with a Creative Commons Attribution, NonCommercial, Share Alike license- http://creativecommons.org/licenses/by-nc-sa/4.0/
# This software is still currently in development. See the GitHub repository for features and notes.

# You must install the listed gems..
# Also note that this software relies on the AWS 2.0 Ruby SDK developer preview, which runs concurrently with the 1.X version
# since I'm too lazy to update the old code right now.

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
    
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
    configfile = File.read('config.json')
    config = JSON.parse(configfile)
    
    # Pull the region. For now, this is hard-coded, will update soon.
    @region = "us-west-2"
    
    # Set AWS config
    AWS.config(access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: 'us-west-2')
    
    # Set application configuration variables
    @QuarantineGroup = "#{config["aws"]["Forensics"]["us-west-1"]["QuarantineSecurityGroup"]}"
    @ForensicsAMI = "#{config["aws"]["Forensics"]["us-west-1"]["AMI"]}"
    @AnalysisSecurityGroup = "#{config["aws"]["Forensics"]["us-west-1"]["AnalysisSecurityGroup"]}"
    @ForensicsSSHKey = "#{config["aws"]["Forensics"]["us-west-1"]["SSHKey"]}"
    @ForensicsUser = "#{config["aws"]["Forensics"]["us-west-1"]["User"]}"

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
   quarantine = @@ec22.modify_instance_attribute(instance_id: "#{@instance_id}", groups: ["#{@QuarantineGroup}"])
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
    # start an empty array to later track and attach the snapshot to a forensics storage volume
    @snap = []
    volumes.each do |vol|
      puts "Volume #{vol} identified; creating snapshot"
      # Create a snapshot of each volume and add the volume and instance ID to the description.
      # We do this since you can't apply a name tag until the snapshot is created, and we don't want to slow down the process.
      timestamp = Time.new
      snap = @@ec22.create_snapshot(
        volume_id: "#{vol}",
        description: "IR volume #{vol} of instance #{@instance_id} at #{timestamp}",
      )
      puts "Snapshot complete with description: IR volume #{vol} of instance #{@instance_id}  at #{timestamp}"
      # get the snapshot id and add it to an array for this instance of the class so we can use it later for forensics
      @snap = @snap += snap.map(&:snapshot_id)
      
    end
  end
  

  def forensics_analysis
    # This method launches an instance and then creates and attaches storage volumes of the IR snapshots. 
    # It also opens Security Group access between the forensics and target instance.
    # Right now it is in Main, but later I will update to run it as a thread, after I get the code working.
    
    # set starting variables 
    alpha = ("f".."z").to_a
    count = 0
    block_device_map = Array.new
    
    # Build the content for the block device mappings to add each snapshot as a volume. 
    # Device mappings start as sdf and continue up to sdz, which is way more than you will ever need.
    @snap.each do |snapshot_id|
      count += 1
      # pull details to get the volume size
      snap_details = @@ec22.describe_snapshots(snapshot_ids: ["#{snapshot_id}"])
      vol_size = snap_details.snapshots.first.volume_size
      # create the string for the device mapping
      device = "/dev/sd" + alpha[count].to_s
      # build the hash we will need later for the bock device mappings
      temphash = Hash.new
      temphash = {
      device_name: "#{device}",
      ebs: {
        snapshot_id: "#{snapshot_id}",
        volume_size: vol_size,
        volume_type: "standard",
        }
      }
      # add the hash to our array
      block_device_map << temphash
      
    end

    # Notify user that this will run in the background in case the snapshots are large and it takes a while
    
    puts "A forensics analysis server is being launched in the background in #{@region} with the name"
    puts "'Forensics' and the snapshots attached as volumes starting at /dev/sdf "
    puts "(which may show as /dev/xvdf). Use host key #{@ForensicsSSHKey} for user #{@ForensicsUser}"
    puts ""
    puts "Press Return to return to the main menu"
    blah = gets.chomp
    
    # Create array to get the snapshot status via API

    snaparray = Array.new
    @snap.each do |snap_id|
      snaparray << "#{snap_id}"
    end 
    
    # Launch the rest as a thread since waiting for the snapshot may otherwise slow the program down.
    
    thread = Thread.new do
          # Get status of snapshots and check to see if any of them are still pending. Loop until they are all ready.
        status = false
        until status == true do
          snap_details = @@ec22.describe_snapshots(snapshot_ids: snaparray)
          snap_details.each do |snapID|
            if snap_details.snapshots.first.state == "completed"
              status = true
            else
              status = false
            end
          end
        end
    
        forensic_instance = @@ec22.run_instances(
          image_id: "#{ @ForensicsAMI}",
          min_count: 1,
          max_count: 1,
          instance_type: "t1.micro",
          key_name: "#{@ForensicsSSHKey}",
          security_group_ids: ["#{@AnalysisSecurityGroup}"],
          placement: {
              availability_zone: "us-west-2a"
            },        
          block_device_mappings: block_device_map
        )
        # Tag the instance so you can find it later
        temp_id = forensic_instance.instances.first.instance_id
        tag = @@ec22.create_tags(
          resources: ["#{temp_id}"],
          tags: [
            {
              key: "SecurityStatus",
              value: "Forensic Analysis Server for #{@instance_id}",
            },
            {
              key: "Name",
              value: "Forensics",
            },
          ],
        )
      end

  end
  
  def store_metadata
    # Method collects the instance metadata before making changes and appends to a local file.
    # Note- currently not working right, need fo convert the has to JSON
    data  = @@ec22.describe_instances(instance_ids: ["#{@instance_id}"])
    timestamp = Time.new
    File.open("ForensicMetadataLog.txt", "a") do |log|
      log.puts "****************************************************************************************"
      log.puts "Incident for instance #{@instance_id} at #{timestamp}"
      log.puts "****************************************************************************************"
      log.puts ""
      metadata = data.to_h
      metadata = metadata.to_json
      log.puts metadata
    end
    puts "Metadata for #{@instance_id} appended to ForensicMetadataLog.txt"
  end

  
end
    
    

# Body code, currently in a test state
#Run basic analysis
menuselect = 0
until menuselect == 7 do
    puts "\e[H\e[2J"
    puts "Welcome to SecuritySquirrel. Please select an action:"
    puts ""
    puts "1. Identify all unmanaged instances"
    puts "2. Initiate Full Quarantine and Forensics on an instance"
    puts "3. Pull and log metadata for an instance"
    puts "7. Exit"
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
      incident_response.store_metadata
      puts ""
      incident_response.quarantine
      puts ""
      incident_response.tag
      puts ""
      incident_response.snapshot
      puts ""
      incident_response.forensics_analysis
    elsif menuselect == "3"
      puts "\e[H\e[2J"
      print "Enter Instance ID:"
      instance_id = gets.chomp
      incident_response = IncidentResponse.new(instance_id)
      incident_response.store_metadata 
    elsif menuselect == "7"
      menuselect = 7
    end
end
