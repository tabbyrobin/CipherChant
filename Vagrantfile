# -*- mode: ruby -*-
# vi: set ft=ruby :

# See: https://www.vagrantup.com/docs/providers/docker/basics#

ENV['VAGRANT_DEFAULT_PROVIDER'] = 'docker'

Vagrant.configure("2") do |config|
    config.vm.provider "docker" do |d|
        d.build_dir = "."
    end
    config.vm.synced_folder ".", "/vagrant", mount_options: ["ro", "dmode=555,fmode=555"]
                            # mount_options: ["dmode=775,fmode=664"]
                            #:mount_options => ["ro"]
end
