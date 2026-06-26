Vagrant.configure("2") do |config| 
	config.vm.define "debian" do |machine|
		machine.vm.box = "debian/bookworm64"
		machine.vm.box_version = "12.20250126.1"
		machine.vm.hostname = "debian-lab"

		machine.vm.network "private_network", ip: "10.10.1.1", 
						    virtualbox__intnet: "windows_net"
		machine.vm.network "private_network", ip: "10.10.10.1", 
						    virtualbox__intnet: "kali_net"

		machine.vm.network "forwarded_port", guest: 5601, host: 5601

		
		machine.vm.provider "virtualbox" do |vb|
			vb.name = "debian-lab"
			vb.memory = 14000
			vb.cpus = 5
		end
		
		machine.vm.provision "shell", path: "debian_script.sh"
	end

	config.vm.define "windows" do |machine|
		machine.vm.box = "gusztavvargadr/windows-11"
		machine.vm.box_version = "2601.0.0"
		machine.vm.hostname = "windows-lab"

		machine.vm.network "private_network", ip: "10.10.1.10", 
							virtualbox__intnet: "windows_net"
		
		machine.vm.provider "virtualbox" do |vb|
			vb.name = "windows-lab"
			vb.memory = 6000
			vb.cpus = 2
		end 

		machine.vm.provision "file",
			source: "config/sysmon-config.xml",
			destination: "C:\\sysmon-config.xml"

		machine.vm.provision "shell",
			inline: "New-Item -ItemType Directory -Force -Path C:\\lab | Out-Null"

		machine.vm.provision "file",
			source: "integration/collect_alerts.py",
			destination: "C:\\lab\\collect_alerts.py"
		
		machine.vm.provision "shell", path: "windows_script.ps1"
	end
	
	config.vm.define "kali" do |machine|
		machine.vm.box = "debian/bookworm64"
		machine.vm.box_version = "12.20250126.1"
		machine.vm.hostname = "kali"
		
		machine.vm.network "private_network", ip: "10.10.10.10",
						    virtualbox__intnet: "kali_net"
		
		machine.vm.provider "virtualbox" do |vb|
			vb.name = "kali"
			vb.memory = 4096
			vb.cpus = 2
		end 

		machine.vm.provision "shell", path: "kali_script.sh"
	end
end		