resource_name :volgactf_qualifier_limits

property :_name, String, name_property: true
property :cookbook, String, default: 'volgactf-qualifier'
property :source, String, default: 'limits.conf'

default_action :create

action :create do
  instance = ::ChefCookbook::Instance::Helper.new(node)

  cookbook_file '/etc/security/limits.conf' do
    cookbook new_resource.cookbook
    source new_resource.source
    owner instance.root
    group node['root_group']
    mode 0644
    action :create
  end
end
