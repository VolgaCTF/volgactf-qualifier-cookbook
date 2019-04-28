resource_name :volgactf_qualifier_user

property :user, String, name_property: true
property :group, String, required: true
property :uid, Integer, default: 600
property :gid, Integer, default: 600

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

  instance = ::ChefCookbook::Instance::Helper.new(node)

  group new_resource.group do
    members [instance.user]
    append true
    action :modify
  end
end
