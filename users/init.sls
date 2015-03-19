# vim: sts=2 ts=2 sw=2 et ai
{% from "users/map.jinja" import users with context %}
{% set used_sudo = [] %}
{% set used_googleauth = [] %}

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
      })
%}
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
{%-   do userlist.update({name:user}) %}
{%- endfor %}


{# include sudo and googleauth states if we need them #}
{# #}
{%- if used_sudo %}
include:
  - users.sudo
{%- endif %}

{%- if used_googleauth %}
include:
  - users.googleauth
{%- endif %}

{# now process all valid users #}
{# #}
{%- for name, user in userlist.items() if not user.absent %}
{%    for group in user.get('groups', []) %}
{{ name }}_{{ group }}_group:
  group:
    - name: {{ group }}
    - present
{%    endfor %}

{{ name }}_user:
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

user_keydir_{{ name }}:
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

user_{{ name }}_private_key:
  file.managed:    
    - name: {{ user.get('home', '/home/{0}'.format(name)) }}/.ssh/{{ key_type }}
    - user: {{ name }}
    - group: {{ user.user_group }}
    - mode: 600    
    - show_diff: False
    - contents_pillar: users:{{ name }}:ssh_keys:privkey
    - require:
      - user: {{ name }}_user
      {% for group in user.get('groups', []) %}
      - group: {{ name }}_{{ group }}_group
      {% endfor %}

user_{{ name }}_public_key:
  file.managed:
    - name: {{ user.get('home', '/home/{0}'.format(name)) }}/.ssh/{{ key_type }}.pub
    - user: {{ name }}
    - group: {{ user.user_group }}
    - mode: 644
    - show_diff: False
    - contents_pillar: users:{{ name }}:ssh_keys:pubkey
    - require:
      - user: {{ name }}_user
      {% for group in user.get('groups', []) %}
      - group: {{ name }}_{{ group }}_group
      {% endfor %}
  {% endif %}

{% if 'ssh_auth_file' in user %}
{{ user.home }}/.ssh/authorized_keys:
  file.managed:
    - user: {{ name }}
    - group: {{ name }}
    - mode: 600
    - contents: |
        {% for auth in user.ssh_auth_file -%}
        {{ auth }}
        {% endfor -%}
{% endif %}

{% if 'ssh_auth' in user %}
{% for auth in user['ssh_auth'] %}
ssh_auth_{{ name }}_{{ loop.index0 }}:
  ssh_auth.present:
    - user: {{ name }}
    - name: {{ auth }}
    - require:
        - file: {{ name }}_user
        - user: {{ name }}_user
{% endfor %}
{% endif %}

{% if 'ssh_auth.absent' in user %}
{% for auth in user['ssh_auth.absent'] %}
ssh_auth_delete_{{ name }}_{{ loop.index0 }}:
  ssh_auth.absent:
    - user: {{ name }}
    - name: {{ auth }}
    - require:
        - file: {{ name }}_user
        - user: {{ name }}_user
{% endfor %}
{% endif %}

{% if 'sudouser' in user and user['sudouser'] %}
sudoer-{{ name }}:
  file.managed:
    - name: {{ users.sudoers_dir }}/{{ name }}
    - user: root
    - group: {{ users.root_group }} 
    - mode: '0440'
{% if 'sudo_rules' in user %}
{% for rule in user['sudo_rules'] %}
"validate {{ name }} sudo rule {{ loop.index0 }} {{ name }} {{ rule }}":
  cmd.run:
    - name: 'visudo -cf - <<<"$rule" | { read output; if [[ $output != "stdin: parsed OK" ]] ; then echo $output ; fi }'
    - stateful: True
    - shell: {{ users.visudo_shell }} 
    - env:
      # Specify the rule via an env var to avoid shell quoting issues.
      - rule: "{{ name }} {{ rule }}"
    - require_in:
      - file: {{ users.sudoers_dir }}/{{ name }}
{% endfor %}

{{ users.sudoers_dir }}/{{ name }}:
  file.managed:
    - contents: |
      {%- for rule in user['sudo_rules'] %}
        {{ name }} {{ rule }}
      {%- endfor %}
    - require:
      - file: sudoer-defaults
      - file: sudoer-{{ name }}
{% endif %}
{% else %}
{{ users.sudoers_dir }}/{{ name }}:
  file.absent:
    - name: {{ users.sudoers_dir }}/{{ name }}
{% endif %}

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

{# now process all users that shall be deleted #}
{# #}
{% for name, user in userlist.items() if user.absent %}
{{ name }}:
{% if 'purge' in user or 'force' in user %}
  user.absent:
    {% if 'purge' in user %}
    - purge: {{ user['purge'] }}
    {% endif %}
    {% if 'force' in user %}
    - force: {{ user['force'] }}
    {% endif %}
{% else %}
  user.absent
{% endif -%}
{{ users.sudoers_dir }}/{{ name }}:
  file.absent:
    - name: {{ users.sudoers_dir }}/{{ name }}
{% endfor %}

{% for user in pillar.get('absent_users', []) %}
{{ user }}:
  user.absent
{{ users.sudoers_dir }}/{{ user }}:
  file.absent:
    - name: {{ users.sudoers_dir }}/{{ user }}
{% endfor %}

{% for group in pillar.get('absent_groups', []) %}
{{ group }}:
  group.absent
{% endfor %}

