resource_name :volgactf_qualifier_user

property :user, String, name_property: true
property :group, String, required: true
property :uid, Integer, default: 600
property :gid, Integer, default: 600
property :instance_user, String, required: true

default_action :create

action :create do
  group new_resource.group do
    gid new_resource.gid
    action :create
  end

  user new_resource.user do
    uid new_resource.uid
    group new_resource.group
    shell '/bin/false'
    system true
    action :create
  end

  group new_resource.group do
    members [new_resource.instance_user]
    append true
    action :modify
  end
end
