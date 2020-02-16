resource_name :volgactf_qualifier_app
property :fqdn, String, name_property: true

property :user, String, default: 'volgactf_qualifier'
property :group, String, default: 'volgactf_qualifier'
property :uid, Integer, default: 600
property :gid, Integer, default: 600

property :development, [TrueClass, FalseClass], default: false
property :ssh_wrapper, [NilClass, String], default: nil

property :database_repo_id, String, default: 'VolgaCTF/volgactf-qualifier-database'
property :database_repo_revision, String, default: 'master'

property :frontend_repo_id, String, default: 'VolgaCTF/volgactf-qualifier-frontend'
property :frontend_repo_revision, String, default: 'master'

property :backend_repo_id, String, default: 'VolgaCTF/volgactf-qualifier-backend'
property :backend_repo_revision, String, default: 'master'

property :customizers, Hash, default: {}
property :default_customizer_repo_id, String, default: 'VolgaCTF/volgactf-qualifier-theme'
property :default_customizer_repo_revision, String, default: 'master'

property :root_dir, String, default: '/opt/volgactf/qualifier'

property :customizer_name, String, default: 'default'
property :customizer_host, String, default: '127.0.0.1'
property :customizer_port, Integer, default: 7037

property :postgres_host, String, required: true
property :postgres_port, Integer, required: true
property :postgres_db, String, required: true
property :postgres_user, String, required: true
property :postgres_password, String, required: true

property :redis_host, String, required: true
property :redis_port, Integer, required: true
property :redis_db, Integer, required: true

property :google_tag_id, [NilClass, String], default: nil

property :mailgun_api_key, [NilClass, String], required: true
property :mailgun_domain, [NilClass, String], required: true

property :smtp_host, [NilClass, String], required: true
property :smtp_port, [NilClass, Integer], required: true
property :smtp_secure, [TrueClass, FalseClass], required: true
property :smtp_username, [NilClass, String], required: true
property :smtp_password, [NilClass, String], required: true

property :twitter_api_consumer_key, [NilClass, String], default: nil
property :twitter_api_consumer_secret, [NilClass, String], default: nil
property :twitter_api_access_token, [NilClass, String], default: nil
property :twitter_api_access_token_secret, [NilClass, String], default: nil

property :telegram_bot_access_token, [NilClass, String], default: nil
property :telegram_chat_id, [NilClass, String], default: nil
property :telegram_socks5_host, [NilClass, String], default: nil
property :telegram_socks5_port, [NilClass, Integer], default: nil
property :telegram_socks5_username, [NilClass, String], default: nil
property :telegram_socks5_password, [NilClass, String], default: nil

property :session_secret, String, required: true

property :backend_host, String, default: '127.0.0.1'
property :backend_port, Integer, default: 8000

property :stream_max_connections, Integer, default: 1024
property :stream_redis_channel, String, default: 'volgactf_qualifier_realtime'

property :queue_prefix, String, default: 'volgactf-qualifier'

property :email_transport, [NilClass, String], default: nil
property :email_address_validator, [NilClass, String], default: nil
property :email_sender_name, String, required: true
property :email_sender_address, String, required: true

property :notification_post_news, [TrueClass, FalseClass], default: true
property :notification_post_twitter, [TrueClass, FalseClass], default: false
property :notification_post_telegram, [TrueClass, FalseClass], default: false

property :post_max_data_size, Integer, default: 1
property :post_max_team_logo_size, Integer, default: 1
property :post_max_task_file_size, Integer, default: 100

property :scheduler_check_contest_interval, Integer, default: 10
property :scheduler_check_tasks_interval, Integer, default: 20
property :scheduler_recalculate_interval, Integer, default: 60

property :num_processes_server, Integer, default: 2
property :num_processes_queue, Integer, default: 2

property :cleanup_upload_dir_enabled, [TrueClass, FalseClass], default: false
property :cleanup_upload_dir_cron_mailto, [NilClass, String], default: nil
property :cleanup_upload_dir_cron_mailfrom, [NilClass, String], default: nil
property :cleanup_upload_dir_cron_minute, String, default: '*'
property :cleanup_upload_dir_cron_hour, String, default: '*'
property :cleanup_upload_dir_cron_day, String, default: '*'
property :cleanup_upload_dir_cron_month, String, default: '*'
property :cleanup_upload_dir_cron_weekday, String, default: '*'

property :backup_enabled, [TrueClass, FalseClass], default: false
property :backup_cron_mailto, [NilClass, String], default: nil
property :backup_cron_mailfrom, [NilClass, String], default: nil
property :backup_cron_minute, String, default: '*'
property :backup_cron_hour, String, default: '*'
property :backup_cron_day, String, default: '*'
property :backup_cron_month, String, default: '*'
property :backup_cron_weekday, String, default: '*'

property :aws_access_key_id, [NilClass, String], default: nil
property :aws_secret_access_key, [NilClass, String], default: nil
property :aws_default_region, [NilClass, String], default: nil
property :aws_s3_bucket, [NilClass, String], default: nil

property :geoip2_city_database, String, required: true
property :geoip2_country_database, String, required: true

property :secure, [TrueClass, FalseClass], required: true
property :proxied, [TrueClass, FalseClass], required: true
property :hsts_max_age, Integer, default: 15_768_000
property :oscp_stapling, [TrueClass, FalseClass], default: true
property :resolvers, Array, default: %w(8.8.8.8 1.1.1.1 8.8.4.4 1.0.0.1)
property :resolver_valid, Integer, default: 600
property :resolver_timeout, Integer, default: 10
property :access_log_options, String, default: 'volgactf_qualifier_log'
property :error_log_options, String, default: 'error'

property :service_group_name, String, default: 'volgactf_qualifier'
property :optimize_delivery, [TrueClass, FalseClass], default: false

default_action :install

action :install do
  volgactf_qualifier_user new_resource.user do
    group new_resource.group
    uid new_resource.uid
    gid new_resource.gid
    action :create
  end

  database_repo_url = "https://github.com/#{new_resource.database_repo_id}"
  frontend_repo_url = "https://github.com/#{new_resource.frontend_repo_id}"
  backend_repo_url = "https://github.com/#{new_resource.backend_repo_id}"

  customizer_entries = new_resource.customizers.dup
  customizer_entries.merge!(
    'default' => {
      'repo_id' => new_resource.default_customizer_repo_id,
      'repo_revision' => new_resource.default_customizer_repo_revision
    }
  )

  customizer_repos = customizer_entries.map do |name, entry|
    {
      name: name,
      repo_url: "https://github.com/#{entry['repo_id']}",
      repo_revision: entry['repo_revision']
    }
  end

  if new_resource.development
    database_repo_url = "git@github.com:#{new_resource.database_repo_id}.git"
    frontend_repo_url = "git@github.com:#{new_resource.frontend_repo_id}.git"
    backend_repo_url = "git@github.com:#{new_resource.backend_repo_id}.git"

    customizer_repos = customizer_entries.map do |name, entry|
      {
        name: name,
        repo_url: "git@github.com:#{entry['repo_id']}.git",
        repo_revision: entry['repo_revision']
      }
    end

    ssh_known_hosts_entry 'github.com' do
      action [:create, :flush]
    end
  end

  instance = ::ChefCookbook::Instance::Helper.new(node)

  directory new_resource.root_dir do
    owner instance.user
    group instance.group
    recursive true
    mode 0755
    action :create
  end

  directory ::File.join(new_resource.root_dir, 'src') do
    owner instance.user
    group instance.group
    mode 0755
    action :create
  end

  directory ::File.join(new_resource.root_dir, 'dist') do
    owner new_resource.user
    group new_resource.group
    mode 0755
    action :create
  end

  dist_cache_dir = ::File.join(new_resource.root_dir, 'dist', '.cache')
  directory dist_cache_dir do
    owner new_resource.user
    group new_resource.group
    mode 0700
    action :create
  end

  directory ::File.join(new_resource.root_dir, 'script') do
    owner instance.user
    group instance.group
    mode 0755
    action :create
  end

  database_dir = ::File.join(new_resource.root_dir, 'database')
  src_frontend_dir = ::File.join(new_resource.root_dir, 'src', 'frontend')
  src_backend_dir = ::File.join(new_resource.root_dir, 'src', 'backend')
  src_customizer_dir = ::File.join(new_resource.root_dir, 'src', 'customizer')

  team_logos_basedir = ::File.join(new_resource.root_dir, 'team_logo_files')
  task_files_basedir = ::File.join(new_resource.root_dir, 'task_files')
  upload_tmp_basedir = ::File.join(new_resource.root_dir, 'upload_tmp')

  directory team_logos_basedir do
    owner new_resource.user
    group new_resource.group
    recursive true
    mode 0755
    action :create
  end

  cookbook_file ::File.join(team_logos_basedir, 'default.png') do
    cookbook 'volgactf-qualifier'
    source 'default.png'
    owner new_resource.user
    group new_resource.group
    mode 0644
    action :create
  end

  directory src_customizer_dir do
    owner instance.user
    group instance.group
    recursive true
    mode 0755
    action :create
  end

  customizer_repos.each do |entry|
    customizer_dir = ::File.join(src_customizer_dir, entry[:name])

    agit customizer_dir do
      repository entry[:repo_url]
      branch entry[:repo_revision]
      user instance.user
      group instance.group
      action :update
    end

    npm_package "Install dependencies at #{customizer_dir}" do
      path customizer_dir
      json true
      user instance.user
      group instance.group
    end
  end

  package 'rsync' do
    action :install
  end

  conf_dir = ::File.join(new_resource.root_dir, 'conf')

  directory conf_dir do
    owner instance.root
    group node['root_group']
    recursive true
    mode 0700
    action :create
  end

  unless new_resource.customizer_name.nil?
    dist_customizer_dir = ::File.join(new_resource.root_dir, 'dist', 'customizer')

    directory dist_customizer_dir do
      owner new_resource.user
      group new_resource.group
      mode 0755
      action :create
    end

    src_specific_customizer_dir = ::File.join(src_customizer_dir, new_resource.customizer_name)

    template ::File.join(new_resource.root_dir, 'script', 'build_customizer') do
      cookbook 'volgactf-qualifier'
      source 'build_customizer.sh.erb'
      owner instance.user
      group instance.group
      variables(
        src_dir: src_specific_customizer_dir,
        dist_dir: dist_customizer_dir,
        dist_cache_dir: dist_cache_dir,
        dist_user: new_resource.user,
        dist_group: new_resource.group,
      )
      mode 0755
      action :create
    end

    execute ::File.join(new_resource.root_dir, 'script', 'build_customizer') do
      cwd src_specific_customizer_dir
      user instance.user
      group instance.group
      action :run
    end

    node_executable_path = nil
    ruby_block 'obtain node executable path' do
      block do
        node_executable_path = `which node`.strip
      end
    end

    customizer_env_file_path = ::File.join(conf_dir, 'customizer')
    template customizer_env_file_path do
      cookbook 'volgactf-qualifier'
      source 'customizer_env.erb'
      owner instance.root
      group node['root_group']
      variables(
        new_resource: new_resource
      )
      mode 0600
      action :create
      notifies :restart, "systemd_unit[#{new_resource.service_group_name}_customizer.service]", :delayed
    end

    systemd_unit "#{new_resource.service_group_name}_customizer.service" do
      content(lazy {
        {
          Unit: {
            Description: 'VolgaCTF Qualifier customizer app',
            PartOf: "#{new_resource.service_group_name}.target",
            After: 'network.target'
          },
          Service: {
            Restart: 'on-failure',
            RestartSec: 5,
            Type: 'simple',
            User: new_resource.user,
            WorkingDirectory: dist_customizer_dir,
            EnvironmentFile: customizer_env_file_path,
            ExecStart: "#{node_executable_path} #{::File.join(dist_customizer_dir, 'bin', 'server.js')}"
          }
        }
      })
      action [:create, :enable, :start]
    end
  end

  agit src_frontend_dir do
    repository frontend_repo_url
    branch new_resource.frontend_repo_revision
    user instance.user
    group instance.group
    action :update
  end

  npm_package 'Install frontend dependencies' do
    path src_frontend_dir
    json true
    user instance.user
    group instance.group
  end

  dist_frontend_dir = ::File.join(new_resource.root_dir, 'dist', 'frontend')

  directory dist_frontend_dir do
    owner new_resource.user
    group new_resource.group
    mode 0775
    action :create
  end

  template ::File.join(new_resource.root_dir, 'script', 'build_frontend') do
    cookbook 'volgactf-qualifier'
    source 'build_frontend.sh.erb'
    owner instance.user
    group instance.group
    variables(
      src_dir: src_frontend_dir,
      build_dir: ::File.join(src_frontend_dir, 'build'),
      dist_dir: ::File.join(new_resource.root_dir, 'dist', 'frontend'),
      dist_user: new_resource.user,
      dist_group: new_resource.group,
      env: {
        'OPTIMIZE' => new_resource.optimize_delivery ? 'yes' : 'no',
        'VOLGACTF_QUALIFIER_CUSTOMIZER_NAME' => new_resource.customizer_name,
        'VOLGACTF_QUALIFIER_CUSTOMIZER_HOST' => new_resource.customizer_host,
        'VOLGACTF_QUALIFIER_CUSTOMIZER_PORT' => new_resource.customizer_port.to_s
      }
    )
    mode 0755
    action :create
  end

  execute ::File.join(new_resource.root_dir, 'script', 'build_frontend') do
    cwd src_frontend_dir
    user instance.user
    group instance.group
    action :run
  end

  agit database_dir do
    repository database_repo_url
    branch new_resource.database_repo_revision
    user instance.user
    group instance.group
    action :update
  end

  npm_package 'Install database dependencies' do
    path database_dir
    json true
    user instance.user
    group instance.group
  end

  knexfile_conf = ::File.join(database_dir, 'knexfile.js')

  template knexfile_conf do
    cookbook 'volgactf-qualifier'
    source 'knexfile.js.erb'
    owner instance.user
    group instance.group
    mode 0644
    variables(
      host: new_resource.postgres_host,
      port: new_resource.postgres_port,
      dbname: new_resource.postgres_db,
      username: new_resource.postgres_user,
      password: new_resource.postgres_password
    )
    action :create
  end

  execute 'Migrate database' do
    command 'npm run knex -- migrate:latest'
    cwd database_dir
    user instance.user
    group instance.group
    environment(
      'HOME' => instance.user_home,
      'USER' => instance.user
    )
    action :run
  end

  agit src_backend_dir do
    repository backend_repo_url
    branch new_resource.backend_repo_revision
    user instance.user
    group instance.group
    action :update
  end

  npm_package 'Install backend dependencies' do
    path src_backend_dir
    json true
    user instance.user
    group instance.group
  end

  dist_backend_dir = ::File.join(new_resource.root_dir, 'dist', 'backend')

  directory dist_backend_dir do
    owner new_resource.user
    group new_resource.group
    mode 0775
    action :create
  end

  template ::File.join(new_resource.root_dir, 'script', 'build_backend') do
    cookbook 'volgactf-qualifier'
    source 'build_backend.sh.erb'
    owner instance.user
    group instance.group
    variables(
      src_dir: src_backend_dir,
      dist_dir: dist_backend_dir,
      dist_cache_dir: dist_cache_dir,
      dist_user: new_resource.user,
      dist_group: new_resource.group,
    )
    mode 0755
    action :create
  end

  execute ::File.join(new_resource.root_dir, 'script', 'build_backend') do
    cwd src_backend_dir
    user instance.user
    group instance.group
    action :run
  end

  directory task_files_basedir do
    owner new_resource.user
    group new_resource.group
    recursive true
    mode 0755
    action :create
  end

  directory upload_tmp_basedir do
    owner new_resource.user
    group new_resource.group
    recursive true
    mode 0755
    action :create
  end

  server_env_file_path = ::File.join(conf_dir, 'server')
  template server_env_file_path do
    cookbook 'volgactf-qualifier'
    source 'server_env.erb'
    owner instance.root
    group node['root_group']
    variables(
      new_resource: new_resource,
      task_files_basedir: task_files_basedir,
      upload_tmp_basedir: upload_tmp_basedir,
      team_logos_basedir: team_logos_basedir,
      dist_frontend_dir: dist_frontend_dir
    )
    mode 0600
    action :create
    notifies :restart, "systemd_unit[#{new_resource.service_group_name}_server.service]", :delayed
  end

  systemd_unit "#{new_resource.service_group_name}_server.service" do
    content(lazy {
      {
        Unit: {
          Description: 'VolgaCTF Qualifier server app',
          PartOf: "#{new_resource.service_group_name}.target",
          After: [
            'network.target',
            "#{new_resource.service_group_name}_customizer.service"
          ],
          Wants: [
            'postgresql.service',
            "redis@#{new_resource.redis_port}.service"
          ]
        },
        Service: {
          Restart: 'on-failure',
          RestartSec: 5,
          Type: 'simple',
          User: new_resource.user,
          WorkingDirectory: dist_backend_dir,
          EnvironmentFile: server_env_file_path,
          ExecStart: "#{node_executable_path} #{::File.join(dist_backend_dir, 'src', 'bin', 'app.js')}"
        }
      }
    })
    action [:create, :enable, :start]
  end

  queue_env_file_path = ::File.join(conf_dir, 'queue')
  template queue_env_file_path do
    cookbook 'volgactf-qualifier'
    source 'queue_env.erb'
    owner instance.root
    group node['root_group']
    variables(
      new_resource: new_resource,
      team_logos_basedir: team_logos_basedir
    )
    mode 0600
    action :create
    notifies :restart, "systemd_unit[#{new_resource.service_group_name}_queue.service]", :delayed
  end

  systemd_unit "#{new_resource.service_group_name}_queue.service" do
    content(lazy {
      {
        Unit: {
          Description: 'VolgaCTF Qualifier queue app',
          PartOf: "#{new_resource.service_group_name}.target",
          After: [
            'network.target',
            "#{new_resource.service_group_name}_customizer.service"
          ],
          Wants: [
            'postgresql.service',
            "redis@#{new_resource.redis_port}.service"
          ]
        },
        Service: {
          Restart: 'on-failure',
          RestartSec: 5,
          Type: 'simple',
          User: new_resource.user,
          WorkingDirectory: dist_backend_dir,
          EnvironmentFile: queue_env_file_path,
          ExecStart: "#{node_executable_path} #{::File.join(dist_backend_dir, 'src', 'bin', 'queue.js')}"
        }
      }
    })
    action [:create, :enable, :start]
  end

  scheduler_env_file_path = ::File.join(conf_dir, 'scheduler')
  template scheduler_env_file_path do
    cookbook 'volgactf-qualifier'
    source 'scheduler_env.erb'
    owner instance.root
    group node['root_group']
    variables(
      new_resource: new_resource
    )
    mode 0600
    action :create
    notifies :restart, "systemd_unit[#{new_resource.service_group_name}_scheduler.service]", :delayed
  end

  systemd_unit "#{new_resource.service_group_name}_scheduler.service" do
    content(lazy {
      {
        Unit: {
          Description: 'VolgaCTF Qualifier scheduler app',
          PartOf: "#{new_resource.service_group_name}.target",
          After: [
            'network.target',
            "#{new_resource.service_group_name}_queue.service"
          ],
          Wants: [
            'postgresql.service',
            "redis@#{new_resource.redis_port}.service"
          ]
        },
        Service: {
          Restart: 'on-failure',
          RestartSec: 5,
          Type: 'simple',
          User: new_resource.user,
          WorkingDirectory: dist_backend_dir,
          EnvironmentFile: scheduler_env_file_path,
          ExecStart: "#{node_executable_path} #{::File.join(dist_backend_dir, 'src', 'bin', 'scheduler.js')}"
        }
      }
    })
    action [:create, :enable, :start]
  end

  ssmtp_helper = nil
  if !node.run_state['ssmtp'].nil? && node.run_state['ssmtp']['installed']
    helper = ::ChefCookbook::SSMTP::Helper.new(node)
  end

  if new_resource.cleanup_upload_dir_enabled
    cleanup_upload_dir_script = ::File.join(new_resource.root_dir, 'script', 'cleanup_upload_dir')

    template cleanup_upload_dir_script do
      cookbook 'volgactf-qualifier'
      source 'cleanup_upload_dir.sh.erb'
      owner instance.user
      group instance.group
      variables(
        run_user: new_resource.user,
        upload_dir: upload_tmp_basedir
      )
      mode 0755
      action :create
    end

    cleanup_upload_dir_command = nil

    ruby_block 'volgactf_qualifier_cleanup_upload_dir' do
      block do
        cronic_installed = !node.run_state['cronic'].nil? && node.run_state['cronic']['installed']
        cleanup_upload_dir_command = "#{cronic_installed ? "#{node.run_state['cronic']['command']} " : ''}#{cleanup_upload_dir_script}"

        unless ssmtp_helper.nil? || new_resource.cleanup_upload_dir_cron_mailto.nil? || new_resource.cleanup_upload_dir_cron_mailfrom.nil?
          cleanup_upload_dir_command += " 2>&1 | #{ssmtp_helper.mail_send_command('Cron volgactf_qualifier_cleanup_upload_dir', new_resource.cleanup_upload_dir_cron_mailfrom, new_resource.cleanup_upload_dir_cron_mailto, cronic_installed)}"
        end
      end
      action :run
    end

    cron 'volgactf_qualifier_cleanup_upload_dir' do
      command lazy { cleanup_upload_dir_command }
      minute new_resource.cleanup_upload_dir_cron_minute
      hour new_resource.cleanup_upload_dir_cron_hour
      day new_resource.cleanup_upload_dir_cron_day
      month new_resource.cleanup_upload_dir_cron_month
      weekday new_resource.cleanup_upload_dir_cron_weekday
      action :create
    end
  end

  nginx_conf 'volgactf_qualifier_log' do
    cookbook 'volgactf-qualifier'
    template 'nginx.log.conf.erb'
    action :create
  end

  nginx_conf 'open_file_cache' do
    cookbook 'volgactf-qualifier'
    template 'nginx.open_file_cache.conf.erb'
    action :create
  end

  nginx_conf 'geoip2' do
    cookbook 'volgactf-qualifier'
    template 'nginx.geoip2.conf.erb'
    variables(
      country_database: new_resource.geoip2_country_database,
      city_database: new_resource.geoip2_city_database
    )
    action :create
  end

  ngx_vhost_variables = {
    secure: new_resource.secure,
    proxied: new_resource.proxied,
    fqdn: new_resource.fqdn,
    access_log_options: new_resource.access_log_options,
    error_log_options: new_resource.error_log_options,
    dist_frontend_dir: dist_frontend_dir,
    task_files_basedir: task_files_basedir,
    team_logos_basedir: team_logos_basedir,
    backend_host: new_resource.backend_host,
    backend_port: new_resource.backend_port,
    post_max_data_size: new_resource.post_max_data_size,
    post_max_team_logo_size: new_resource.post_max_team_logo_size,
    post_max_task_file_size: new_resource.post_max_task_file_size,
    optimize: new_resource.optimize_delivery
  }

  if new_resource.secure && !new_resource.proxied
    tls_rsa_certificate new_resource.fqdn do
      action :deploy
    end

    tls = ::ChefCookbook::TLS.new(node)

    ngx_vhost_variables.merge!(
      certificate_entries: [
        tls.rsa_certificate_entry(new_resource.fqdn)
      ],
      hsts_max_age: new_resource.hsts_max_age,
      oscp_stapling: new_resource.oscp_stapling,
      resolvers: new_resource.resolvers,
      resolver_valid: new_resource.resolver_valid,
      resolver_timeout: new_resource.resolver_timeout
    )

    if tls.has_ec_certificate?(new_resource.fqdn)
      tls_ec_certificate new_resource.fqdn do
        action :deploy
      end

      ngx_vhost_variables[:certificate_entries] << tls.ec_certificate_entry(new_resource.fqdn)
    end
  end

  nginx_vhost 'volgactf-qualifier' do
    cookbook 'volgactf-qualifier'
    template 'nginx.conf.erb'
    variables(lazy {
      ngx_vhost_variables.merge(
        access_log: ::File.join(
          node.run_state['nginx']['log_dir'],
          "volgactf_qualifier_server_access.log"
        ),
        error_log: ::File.join(
          node.run_state['nginx']['log_dir'],
          "volgactf_qualifier_server_error.log"
        )
      )
    })
    action :enable
  end

  template ::File.join(new_resource.root_dir, 'script', 'cli') do
    cookbook 'volgactf-qualifier'
    source 'cli.sh.erb'
    owner instance.user
    group instance.group
    variables(
      dist_dir: dist_backend_dir,
      dist_cache_dir: dist_cache_dir,
      env: {
        'VOLGACTF_QUALIFIER_SESSION_SECRET' => new_resource.session_secret,
        'VOLGACTF_QUALIFIER_FQDN' => new_resource.fqdn,
        'REDIS_HOST' => new_resource.redis_host,
        'REDIS_PORT' => new_resource.redis_port,
        'REDIS_DB' => new_resource.redis_db,
        'VOLGACTF_QUALIFIER_TEAM_LOGOS_DIR' => team_logos_basedir,
        'VOLGACTF_QUALIFIER_QUEUE_PREFIX' => new_resource.queue_prefix,
        'VOLGACTF_QUALIFIER_STREAM_REDIS_CHANNEL' => new_resource.stream_redis_channel,
        'POSTGRES_HOST' => new_resource.postgres_host,
        'POSTGRES_PORT' => new_resource.postgres_port,
        'POSTGRES_DBNAME' => new_resource.postgres_db,
        'POSTGRES_USERNAME' => new_resource.postgres_user,
        'POSTGRES_PASSWORD' => new_resource.postgres_password
      }
    )
    mode 0755
    action :create
  end

  dbreset_script = ::File.join(new_resource.root_dir, 'script', 'dbreset')

  template dbreset_script do
    cookbook 'volgactf-qualifier'
    source 'dbreset.sh.erb'
    owner instance.user
    group instance.group
    variables(
      run_user: new_resource.user,
      pg_host: new_resource.postgres_host,
      pg_port: new_resource.postgres_port,
      pg_dbname: new_resource.postgres_db,
      pg_username: new_resource.postgres_user,
      pg_password: new_resource.postgres_password
    )
    mode 0755
    action :create
  end

  if new_resource.backup_enabled
    execute 'pip install awscli' do
      action :run
    end

    backup_script = ::File.join(new_resource.root_dir, 'script', 'backup')

    template backup_script do
      cookbook 'volgactf-qualifier'
      source 'backup.sh.erb'
      owner instance.user
      group instance.group
      variables(
        run_user: new_resource.user,
        team_logo_file_dir: team_logos_basedir,
        task_file_dir: task_files_basedir,
        pg_host: new_resource.postgres_host,
        pg_port: new_resource.postgres_port,
        pg_dbname: new_resource.postgres_db,
        pg_username: new_resource.postgres_user,
        pg_password: new_resource.postgres_password,
        aws_access_key_id: new_resource.aws_access_key_id,
        aws_secret_access_key: new_resource.aws_secret_access_key,
        aws_default_region: new_resource.aws_default_region,
        aws_s3_bucket: new_resource.aws_s3_bucket
      )
      mode 0755
      action :create
    end

    backup_command = nil

    ruby_block 'volgactf_qualifier_backup' do
      block do
        cronic_installed = !node.run_state['cronic'].nil? && node.run_state['cronic']['installed']
        backup_command = "#{cronic_installed ? "#{node.run_state['cronic']['command']} " : ''}#{backup_script}"

        unless ssmtp_helper.nil? || new_resource.backup_cron_mailto.nil? || new_resource.backup_cron_mailfrom.nil?
          backup_command += " 2>&1 | #{ssmtp_helper.mail_send_command('Cron volgactf_qualifier_backup', new_resource.backup_cron_mailfrom, new_resource.backup_cron_mailto, cronic_installed)}"
        end
      end
      action :run
    end

    cron 'volgactf_qualifier_backup' do
      command lazy { backup_command }
      minute new_resource.backup_cron_minute
      hour new_resource.backup_cron_hour
      day new_resource.backup_cron_day
      month new_resource.backup_cron_month
      weekday new_resource.backup_cron_weekday
      action :create
    end
  end

  systemd_unit "#{new_resource.service_group_name}.target" do
    content(lazy {
      {
        Unit: {
          Description: 'VolgaCTF Qualifier',
          Wants: [
            "#{new_resource.service_group_name}_customizer.service",
            "#{new_resource.service_group_name}_server.service",
            "#{new_resource.service_group_name}_queue.service",
            "#{new_resource.service_group_name}_scheduler.service"
          ]
        },
        Install: {
          WantedBy: 'multi-user.target'
        }
      }
    })
    action [:create, :enable, :start]
  end
end
