# vim: sts=2 ts=2 sw=2 et ai
{% from "users/map.jinja" import users with context %}
{% set used_sudo = False %}
{% set used_googleauth = False %}

#
# TODO
# add authgroups:
#   * an authgroup is a group of users that shall have access to a unix account on a host
#     -> this is a separate sls
#
# add accounts:
#   * if an accounts pillar exists, only add users on this host that are mentioned in accounts.
#     * groups of users to add
#     * additional single users to add
#     * absent users: make sure, these are deleted
#
# -> put authgroups and accounts to separate sls files, keep changes to init.sls minimal


{# prepare userlist dictionary so we can avoid multiple checks and simplify syntax later on #}
{# #}
{%- set userlist = pillar.get('users', {})  %}

{%- for name, user in userlist.items() %}

{%-   if user == None %}
{%-     set user = {} %}
{%-   endif %}
{%-   do user.update({
                'absent'     : user.get('absent', False),
                'sudouser'   : user.get('sudouser', False),
                'google_auth': user.get('google_auth', False),
                'prime_group': user.get('prime_group', {}),
                'home'       : user.get('home', "/home/%s" % name),
                'ssh_auth'   : user.get('ssh_auth', []),
                'ssh_auth.absent'   : user.get('ssh_auth.absent', []),
      })
%}
{#              NOTE: "ssh_auth.absent" is ambiguous. it should be renamed to e.g. ssh_auth_absent #}
{##}
{# add more defaults that we could not add with previous .update #}
{%-   do user.update({
                'user_group' : user.prime_group.get('name',name)
      })
%}
{%-   if user.sudouser %}
{%-     set  used_sudo = True %}
{%-   endif %}
{%-   if user.google_auth %}
{%-     set used_googleauth = True %}
{%-   endif %}
{#    finally update the list of users to apply the defaults  #}
{%-   do userlist.update({name:user}) %}
{%- endfor %}


# include sudo and googleauth states if we need them
#
{%- if used_sudo %}
include:
  - users.sudo
{%- endif %}

{%- if used_googleauth %}
include:
  - users.googleauth
{%- endif %}

# now process all valid users
#
{%- for name, user in userlist.items() if not user.absent %}

# create missing groups
#
{% for group in user.get('groups', []) %}
users_group_{{ name }}_{{ group }}:
  group:
    - name: {{ group }}
    - present
{% endfor %}


# create homedir, main group and user
#
users_account_{{ name }}:
  {% if user.get('createhome', True) %}
  file.directory:
    - name: {{ user.home }}
    - user: {{ name }}
    - group: {{ user.user_group }}
    - mode: {{ user.get('user_dir_mode', '0750') }}
    - require:
      - user: {{ name }}
      - group: {{ user.user_group }}
  {%- endif %}
  group.present:
    - name: {{ user.user_group }}
    {%- if 'gid' in user.prime_group %}
    - gid: {{ user.prime_group.gid }}
    {%- elif 'uid' in user %}
    - gid: {{ user.uid }}
    {%- endif %}
  user.present:
    - name: {{ name }}
    - home: {{ user.home }}
    - shell: {{ user.get('shell', users.get('shell', '/bin/bash')) }}
    {% if 'uid' in user -%}
    - uid: {{ user.uid }}
    {% endif -%}
    {% if 'password' in user -%}
    - password: '{{ user.password }}'
    {% endif -%}
    {% if 'gid' in user.prime_group -%}
    - gid: {{ user.prime_group.gid }}
    {% else -%}
    - gid_from_name: True
    {% endif -%}
    {% if 'fullname' in user %}
    - fullname: {{ user.fullname }}
    {% endif -%}
    {% if not user.get('createhome', True) %}
    - createhome: False
    {% endif %}
    {% if 'expire' in user -%}
    - expire: {{ user.expire }}
    {% endif -%}
    - remove_groups: {{ user.get('remove_groups', 'False') }}
    - groups:
      - {{ user.user_group }}
      {% for group in user.get('groups', []) -%}
      - {{ group }}
      {% endfor %}
    - require:
      - group: {{ user.user_group }}
      {% for group in user.get('groups', []) -%}
      - group: {{ group }}
      {% endfor %}


# create .ssh dir for user
#
users_keydir_{{ name }}:
  file.directory:
    - name: {{ user.get('home', '/home/{0}'.format(name)) }}/.ssh
    - user: {{ name }}
    - group: {{ user.user_group }}
    - makedirs: True
    - mode: 700
    - require:
      - user: {{ name }}
      - group: {{ user.user_group }}
      {%- for group in user.get('groups', []) %}
      - group: {{ group }}
      {%- endfor %}

  {% if 'ssh_keys' in user %}
  {% set key_type = 'id_' + user.get('ssh_key_type', 'rsa') %}

# write users private key to .ssh
#
users_private_key_{{ name }}:
  file.managed:    
    - name: {{ user.get('home', '/home/{0}'.format(name)) }}/.ssh/{{ key_type }}
    - user: {{ name }}
    - group: {{ user.user_group }}
    - mode: 600    
    - show_diff: False
    - contents_pillar: users:{{ name }}:ssh_keys:privkey
    - require:
      - user: {{ name }}
      {% for group in user.get('groups', []) %}
      - group: {{ group }}
      {% endfor %}

# write users public key to .ssh
#
users_public_key_{{ name }}:
  file.managed:
    - name: {{ user.get('home', '/home/{0}'.format(name)) }}/.ssh/{{ key_type }}.pub
    - user: {{ name }}
    - group: {{ user.user_group }}
    - mode: 644
    - show_diff: False
    - contents_pillar: users:{{ name }}:ssh_keys:pubkey
    - require:
      - user: {{ name }}
      {% for group in user.get('groups', []) %}
      - group: {{ group }}
      {% endfor %}
  {% endif %}


# replace users authorized keys file with contents of "ssh_auth_file"
#
{% if 'ssh_auth_file' in user %}
users_authfile_{{ name }}:
  file.managed:
    - name: {{ user.home }}/.ssh/authorized_keys
    - user: {{ name }}
    - group: {{ name }}
    - mode: 600
    - contents: |
        {% for auth in user.ssh_auth_file -%}
        {{ auth }}
        {% endfor -%}
{% endif %}


# add all keys from ssh_auth to authorized_keys
#
{% for auth in user.ssh_auth %}
users_ssh_auth_{{ name }}_{{ loop.index0 }}:
  ssh_auth.present:
    - user: {{ name }}
    - name: {{ auth }}
    - require:
        - file: users_account_{{ name }}
        - user: users_account_{{ name }}
{% endfor %}

# remove absent keys from authorized_keys file
{# "ssh_auth.absent" is awful :( i am gonna rename this! #}
{% for auth in user['ssh_auth.absent'] %}
users_ssh_auth_delete_{{ name }}_{{ loop.index0 }}:
  ssh_auth.absent:
    - user: {{ name }}
    - name: {{ auth }}
    - require:
        - file: users_account_{{ name }}
        - user: users_account_{{ name }}
{% endfor %}


# add sudo rules for a user
#
{% if user.sudouser %}
users_sudoer_{{ name }}:
  file.managed:
    - name: {{ users.sudoers_dir }}/{{ name }}
    - user: root
    - group: {{ users.root_group }} 
    - mode: '0440'

# add additional sudo rules
#
{% if 'sudo_rules' in user %}
{% for rule in user['sudo_rules'] %}
# validate sudo rules
#
users_validate_sudo_rule_{{ name }}_{{ loop.index0 }}:
  cmd.run:
    - name: 'visudo -cf - <<<"$rule" | { read output; if [[ $output != "stdin: parsed OK" ]] ; then echo $output ; fi }'
    - stateful: True
    - shell: {{ users.visudo_shell }} 
    - env:
      # Specify the rule via an env var to avoid shell quoting issues.
      - rule: "{{ name }} {{ rule }}"
    - require_in:
      - file: users_sudoer_rules_{{ name }}
{% endfor %}

# write rules after validation
#
users_sudoer_rules_{{ name }}:
  file.managed:
    - name: {{ users.sudoers_dir }}/{{ name }}:
    - contents: |
      {%- for rule in user['sudo_rules'] %}
        {{ name }} {{ rule }}
      {%- endfor %}
    - require:
      - file: sudoer-defaults
      - file: users_sudoer-{{ name }}
{% endif %}
{% else %}
# remove rules if none defined for this user
#
users_sudoer_{{ name }}:
  file.absent:
    - name: {{ users.sudoers_dir }}/{{ name }}
{% endif %}

# google auth 
#
{%- if user.google_auth %}
{%- for svc in user['google_auth'] %}
googleauth-{{ svc }}-{{ name }}:
  file.managed:
    - replace: false
    - name: {{ users.googleauth_dir }}/{{ name }}_{{ svc }}
    - contents_pillar: 'users:{{ name }}:google_auth:{{ svc }}'
    - user: root
    - group: {{ users.root_group }}
    - mode: 600
    - require:
      - pkg: googleauth-package
{%- endfor %}
{%- endif %}

{% endfor %}

# now process all users and groups that shall be deleted
#
{% for name, user in userlist.items() if user.absent %}
# remove user
users_absent_{{ name }}:
  user.absent:
    - name: {{ name }}
    - purge: {{ user.get('purge', False) }}
    - force: {{ user.get('force', False) }}

# also remove sudo configuration
users_sudoers_absent_{{ name }}:
  file.absent:
    - name: {{ users.sudoers_dir }}/{{ name }}
{% endfor %}

# backward compatibility: alternative way of removing users and groups
#
{% for user in pillar.get('absent_users', []) %}
users_absent2_{{ user }}:
  user.absent:
    - name: {{ user }}:
  file.absent:
    - name: {{ users.sudoers_dir }}/{{ user }}
{% endfor %}

{% for group in pillar.get('absent_groups', []) %}
users_group_absent2_{{ group }}:
  group.absent:
    - name: {{ group }}
{% endfor %}

