<?php
/**
 * New user identity MOD
 *
 * Populates a new user's default identity from LDAP on their first visit.
 *
 * This plugin requires that a working public_ldap directory be configured.
 *
 * @version @package_version@
 * @author seregin@soho-service.ru
 * @license GNU GPLv3+
 */
class new_user_identity extends rcube_plugin
{
    public $task = 'login';

    private $rc;
    private $ldap;
    private $ldap_config;
    private $log_file;

    function init(){
        $this->rc = rcmail::get_instance();
        $this->log_file = null; //new_user_identity_debug.log;

        $this->add_hook('user_create', array($this, 'lookup_ldap_email'));
    }

    function lookup_ldap_email($args){
        $this->write_log("hooked user_create args", $args);
        $user=array();
        if ($this->search_user(idn_to_utf8($args['user']), $user)) {
            $this->write_log("found successfully");
            
            $args['user_name']  = $user['username'];
            $args['user_email'] = '';

            if(isset($user['email']) && strpos($user['email'], '@')){
                $args['user_email'] = $user['email'];
            }
        }

        return $args;
    }
    
    private function search_user($username, &$data){
        $this->load_config();
        if (!$this->ldap) {
            $this->ldap_config = array_merge(array(), (array)$this->rc->config->get('ldap_public')[$this->rc->config->get('new_user_identity_addressbook')]);

            $this->write_log('connect dn=' . $this->ldap_config['bind_dn']);

            $this->ldap = new Net_LDAP3(array(
                'hosts' => $this->ldap_config['hosts'],
                'port'  => isset($this->ldap_config['port']) ? $this->ldap_config['port'] : 389,
                'use_tls' => false,
                'ldap_version'  => 3,
                'service_bind_dn' => $this->ldap_config['bind_dn'],
                'service_bind_pw' => $this->ldap_config['bind_pass'],
                'root_dn'         => $this->ldap_config['base_dn'],
                'referrals' => 0
            ));

            $this->ldap->config_set('log_hook', array($this, 'debug_ldap'));

            if(!$this->ldap->connect()){
                return false;
            };

            $this->write_log("connected");

            if(!$this->ldap->bind($this->ldap_config['bind_dn'], $this->ldap_config['bind_pass'])){
                $this->write_log('bind LDAP failed');
                return false;
            };

        };

        $found = $this->ldap->search(
            $this->ldap_config['base_dn'],
            "(&(mail=*)(objectClass=user)(samAccountName=$username)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            'sub',
            array('distinguishedName','samAccountName','mail')
        );


        if(FALSE === $found){
            return false;
        }

        foreach($found->entries(true) as $dn=>$attr){
            $data['username'] = $attr['samaacountname'];
            $data['email'] = $attr['mail'];
        }

        return true;

    }

    private function write_log($msg, $data = null){
        if(is_null($this->log_file)) return;
        $this->rc->write_log($this->log_file, $msg . (is_null($data) ? "" : "\r\n" . var_export($data, true)));
    }

    function debug_ldap($level, $msg){
        $msg = implode("\n", $msg);
        $this->write_log($msg);
    }
}