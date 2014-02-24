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
require 'halo-api-lib'
require 'httparty'

# class for chef integration
class ConfigManagement
  # This class integrates with Chef for configuration management. Right now it only has one method. Need to move initialization to an init method when I add more functionality. 
  def analyze
    # This method polls EC2 and polls Chef to identify any unmanaged instances.
    # Right now it uses the instance name since there is a bug in the Ridley SDK that limits pulling alternate attribures, but plan is to fix that soon
    
    # Load configuration and credentials from a JSON file

    configfile = File.read('config.json')
    config = JSON.parse(configfile)
    
    # set AWS config

    AWS.config(access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: "#{$region}")


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

# class for incident resposne functions like quarantine.
class IncidentResponse
  def initialize(instance_id)
    @instance_id = instance_id
    
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
    configfile = File.read('config.json')
    config = JSON.parse(configfile)
    
    # Set AWS config
    AWS.config(access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: "#{$region}")
    
    # Set application configuration variables. Im hunting for a more efficient way to dynamically pull the region,
    # but haven't found one that works yet. Thus, for now, sticking with elsif. Suggestions appreciated.
    
    # Remember that not all AWS services are available in all regions. Everything in this version of the tool should work.
    

    if $region == "us-west-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-west-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-west-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-west-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-west-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-west-1"]["User"]}"
    elsif $region == "us-west-2"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-west-2"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-west-2"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-west-2"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-west-2"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-west-2"]["User"]}"
    elsif $region == "us-east-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-east-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-east-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-east-1"]["User"]}"
    elsif $region == "eu-west-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["eu-west-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["eu-west-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["eu-west-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["eu-west-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["eu-west-1"]["User"]}"
    elsif $region == "ap-southeast-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["User"]}"
    elsif $region == "ap-southeast-2"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["User"]}"
    elsif $region == "ap-northeast-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["User"]}"
    elsif $region == "sa-east-1"
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["sa-east-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["sa-east-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["sa-east-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["sa-east-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["sa-east-1"]["User"]}"
    else
      #default to us-east-1 in case something fails
      @QuarantineGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["QuarantineSecurityGroup"]}"
      @ForensicsAMI = "#{config["aws"]["RegionSettings"]["us-east-1"]["AMI"]}"
      @AnalysisSecurityGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["AnalysisSecurityGroup"]}"
      @ForensicsSSHKey = "#{config["aws"]["RegionSettings"]["us-east-1"]["SSHKey"]}"
      @ForensicsUser = "#{config["aws"]["RegionSettings"]["us-east-1"]["User"]}"
    end

    # Fill the ec2 class
    @@ec2 = AWS.ec2 #=> AWS::EC2
    @@ec2.client #=> AWS::EC2::Client
    
    # Added code for the AWS SDK version 2.0 (aws-sdk-core) that has more functions, but kills some existing code so not fully converting to it yet.
    
    Aws.config = { access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: "#{$region}" }
    
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
      puts "Snapshots complete with description: IR volume #{vol} of instance #{@instance_id}  at #{timestamp}"
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

# class for automated assessment functions, including Qualys and CloudPassage integration.
class Assess
  def initialize(instance_id)
    @instance_id = instance_id
    
    # Load configuration and credentials from a JSON file. Right now hardcoded to config.json in the app drectory.
    configfile = File.read('config.json')
    config = JSON.parse(configfile)
    
    # Set AWS config
    AWS.config(access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: "#{$region}")
    
    # Set application configuration variables. Im hunting for a more efficient way to dynamically pull the region,
    # but haven't found one that works yet. Thus, for now, sticking with elsif. Suggestions appreciated.
    
    # Remember that not all AWS services are available in all regions. Everything in this version of the tool should work.
    

    if $region == "us-west-1"
      @AssessSecurityGroup = "#{config["aws"]["RegionSettings"]["us-west-1"]["AssessSecurityGroup"]}"
    elsif $region == "us-west-2"
      @AssessSecurityGroup = "#{config["aws"]["RegionSettings"]["us-west-2"]["AssessSecurityGroup"]}"
    elsif $region == "us-east-1"
      @AssessSecurityGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["AssessSecurityGroup"]}"
    elsif $region == "eu-west-1"
      @AssessSecurityGroup = "#{config["aws"]["RegionSettings"]["eu-west-1"]["AssessSecurityGroup"]}"
    elsif $region == "ap-southeast-1"
      @AssessSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-1"]["AssessSecurityGroup"]}"
    elsif $region == "ap-southeast-2"
      @AssessSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-southeast-2"]["AssessSecurityGroup"]}"
    elsif $region == "ap-northeast-1"
      @AssessSecurityGroup = "#{config["aws"]["RegionSettings"]["ap-northeast-1"]["AssessSecurityGroup"]}"
    elsif $region == "sa-east-1"
      @AssessSecurityGroup = "#{config["aws"]["RegionSettings"]["sa-east-1"]["AssessSecurityGroup"]}"
    else
      #default to us-east-1 in case something fails
      @AssessSecurityGroup = "#{config["aws"]["RegionSettings"]["us-east-1"]["AssessSecurityGroup"]}"
    end

    # Fill the ec2 class
    @@ec2 = AWS.ec2 #=> AWS::EC2
    @@ec2.client #=> AWS::EC2::Client
    
    # Added code for the AWS SDK version 2.0 (aws-sdk-core) that has more functions, but kills some existing code so not fully converting to it yet.
    
    Aws.config = { access_key_id: "#{config["aws"]["AccessKey"]}", secret_access_key: "#{config["aws"]["SecretKey"]}", region: "#{$region}" }
    
    @@ec22 = Aws::EC2.new
    @@ec22 = Aws.ec2
    
    # set Qualys credentials and scanner source
        @qualysauth = {:username => "#{config["qualys"]["username"]}", :password => "#{config["qualys"]["password"]}"}
        @qualys_scanner_ip = "#{config["qualys"]["scanner_ip"]}"
        
        # set CloudPassage credentials
        @halo_id = "#{config["cloudpassage"]["id"]}"
        @halo_secret = "#{config["cloudpassage"]["secret"]}"
        @halo_base_url = "https://portal.cloudpassage.com/"
        @scanner_zone = "#{config["cloudpassage"]["VA_scanner_zone"]}"
  end
  
  def open_security_group
    # add a security group to the instance to allow scanning from the Qualys scanner.
    # this code *does not* check to see if the instance is within the allowed number of
    # security groups. Will add that later. Thus it will fail if you go over that limit.
    
    # get instance details
    instance_details = @@ec22.describe_instances(
      instance_ids: ["#{@instance_id}"],
    )
    
    # identify IP and security groups
    puts "Identifying internal IP address..."
    instance_IP = instance_details.reservations.first.instances.first.private_ip_address
    puts "IP address is #{instance_IP}"
    puts ""
    puts "Identifying current security groups..."
    securitygroups = instance_details.reservations.first.instances.first.security_groups
    secgroupID = securitygroups.map(&:group_id)
    puts secgroupID
    puts ""
    puts "Adding the scan security group"
    secgroupID << @AssessSecurityGroup
    quarantine = @@ec22.modify_instance_attribute(instance_id: "#{@instance_id}", groups: secgroupID)
    puts "Scan group added, instance is now in: #{secgroupID}"
    puts ""
    puts "**Warning** This version of the code does *not* revert the security group after the scan."
    puts "This feature will be added soon, but for now you need to manually correct."
    puts ""
  end
  
  def qualys
    # method for initiating a Qualys scan on a designated instance
    puts "Note- you must obtain permission from Amazon before performing the standard scan"
    puts "in the code below. The Qualys API does not current support pre-auth scans."
    puts "Type Y to continue:"
    check = gets.chomp
    if check == "Y" then
      # get instance details
      instance_details = @@ec22.describe_instances(
        instance_ids: ["#{@instance_id}"],
      )
    
      # identify IP and security groups
      instance_IP = instance_details.reservations.first.instances.first.private_ip_address
     timestamp = Time.new
     scan =(HTTParty.post("https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/scan/",
          :basic_auth => @qualysauth,
          :query => { 
            :action => "launch",
            :scan_title => "SecuritySquirrel Scan at #{timestamp}", 
            :ip => "#{instance_IP}",
            :option_title => "Initial Options",
            :iscanner_name =>  "us-west-2" 
          },
          :headers => { "X-Requested-With" => "ruby httparty"}))
          puts "Launching Qualys scan named: SecuritySquirrel Scan at #{timestamp}"
   end
 end
 
 def halo_open_scan
   # This method alters the firewall policy in CloudPassage Halo to allow a Qualys scan.
   # Open a connection to CloudPassage
   
   puts "Opening Halo client"
   halo = Halo::Client.new
   halo.base_url = @halo_base_url
   halo.key_id = @halo_id 
   halo.key_secret = @halo_secret
   token = halo.token

   # Get server IP address from Amazon to match with Halo, since it doesn't use the AWS instance ID
   instance_details = @@ec22.describe_instances(
     instance_ids: ["#{@instance_id}"],
   )
   
   server = instance_details.reservations.first.instances.first.private_ip_address

   # Pull a list of all Halo servers, then identify the ID of the one we are looking for.
   # This is somewhat inefficient, but the Halo Ruby SDK is still pre-release and functionality is being flushed out.
   puts "Finding server #{server} in Halo"

   list = Halo::Servers.all halo
   group_list = Halo::ServerGroups.all halo
   policy_list = Halo::FirewallPolicies.all halo
   existing_zones = Halo::FirewallZones.all halo
   
   matching_fw = nil
   matching_fw_id = nil

   group_list.each do |gr|
     member_list = gr.servers halo
     member_list.each do |svr|
       # Check the network interfaces and match on the ID
       svr.interfaces.each do |ifc|
         if ifc.ip_address == server
          # puts "Group: #{gr.to_s}"
          # puts "Server: #{svr.to_s}"
          # puts "  platform=#{svr.platform}"
         
           #Get the firewall policy ID
           if (svr.platform == "windows")
             matching_fw_id = gr.windows_firewall_policy_id
           else
             matching_fw_id = gr.linux_firewall_policy_id
           end
           #Fill the firewall policy object based on that ID
           if (matching_fw_id != nil)
             policy_list.each do |fw|
               matching_fw = fw if (fw.id == matching_fw_id)
             end
           end
           puts "Changing Halo firewall policy #{matching_fw.name} to allow scanning from Qualys scanner at #{@scanner_zone}"
           
           #Find existing firewall zone
           puts "Finding firewall zone in Halo"
           zone = nil
           existing_zones.each do |curzone|
              if (curzone.ip_address == @scanner_zone)
                zone = curzone
              end
           end
         
           #Add the firewall rule. This assumes you have a zone set up for the scanner. 
           #CloudPassage has much better sample code for handling this, but I wanted
           # to keep it as simple as possible for this PoC code. Thus, it will break more
           # and there is more manual work to ensure you set the zone up ahead of time.
         
           srcObj = { 'type' => 'FirewallZone', 'id' => zone.id }
           ruleObj = { 'chain' => 'INPUT', 'action' => 'ACCEPT', 'active' => 'true' }
           ruleObj['firewall_source'] = srcObj
           status = matching_fw.add_rule(halo,ruleObj,1) # position=1 is highest priority
           puts "Adding new rule, status=#{status}"        
         end
       end
   end
 end
 end
end

def region
  # A method for setting the availability zone
  # Pull the configuration so we only show regions that are configured
  configfile = File.read('config.json')
  config = JSON.parse(configfile)
  
   puts "\e[H\e[2J"
   puts "Current region: #{$region}. Select a new region:"
   puts "(Only regions you have configured are shown)"
   puts ""
   puts ""

   if config["aws"]["RegionSettings"].has_key?('us-east-1')
        puts "1. us-east-1 (Virginia)"
      end
   if config["aws"]["RegionSettings"].has_key?('us-west-1')
        puts "2. us-west-1 (California)"
  end
    if config["aws"]["RegionSettings"].has_key?('us-west-2')
       puts "3. us-west-2 (Oregon)"
  end
    if config["aws"]["RegionSettings"].has_key?('eu-west-1')
        puts "4. eu-west-1 (Ireland)"
    end
    if config["aws"]["RegionSettings"].has_key?('ap-southeast-1')
        puts "5. ap-southeast-1 (Singapore)"
    end
    if config["aws"]["RegionSettings"].has_key?('ap-southeast-2')
       puts "6. ap-southeast-2 (Sydney)"
    end
    if config["aws"]["RegionSettings"].has_key?('ap-northeast-1')
        puts "7. ap-northeast-1 (Tokyo)"
    end
    if config["aws"]["RegionSettings"].has_key?('sa-east-1')
        puts "8. sa-east-1 (Sao Paulo)"
    end

  
  puts ""
  print "New region: "
  option = gets.chomp
  $region = case option
    when "1" then "us-east-1"
    when "2" then "us-west-1"
    when "3" then "us-west-2"
    when "4" then "eu-west-1"
    when "5" then "ap-southeast-1"
    when "6" then "ap-southeast-2"
    when "7" then "ap-northeast-1"
    when "8" then "sa-east-1"
    else puts "Error, select again:"
   end

end


# Body code
# Load defaults. Rightnow, just the region.
configfile = File.read('config.json')
config = JSON.parse(configfile)
$region = "#{config["aws"]["DefaultRegion"]}"

menuselect = 0
until menuselect == 7 do
    puts "\e[H\e[2J"
    puts "Welcome to SecuritySquirrel. Please select an action:"
    puts "Current region is #{$region}"
    puts ""
    puts "1. Identify all unmanaged instances"
    puts "2. Initiate automated Quarantine and Forensics on an instance"
    puts "3. Pull and log metadata for an instance"
    puts "4. Assess an instance"
    puts "6. Change region"
    puts "7. Exit"
    puts ""
    print "Select: "
    menuselect = gets.chomp
    if menuselect == "1"
      managed_test = ConfigManagement.new
      managed_test.analyze
      puts "Press Return to return to the main menu"
      blah = gets.chomp
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
      puts "Press Return to return to the main menu"
      blah = gets.chomp
    elsif menuselect == "4"
      puts "\e[H\e[2J"
      print "Enter Instance ID:"
      instance_id = gets.chomp
      assess = Assess.new(instance_id)
      assess.open_security_group
      assess.halo_open_scan
      assess.qualys
      gets.chomp
    elsif menuselect == "6"
      region
    elsif menuselect == "7"
      menuselect = 7
    else 
      puts "Error, please select a valid option"
    end
end
