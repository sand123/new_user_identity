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
    private $is_data_ready;
    private $attr_username;
    private $attr_email;
    private $attr_dn;

    public function init(){
        $this->rc = rcmail::get_instance();
        $this->log_file = null; //"new_user_identity_debug.log";

        $this->is_data_ready = false;
        $this->attr_dn = "";
        $this->attr_email ="";
        $this->attr_username="";

        $this->add_hook('user_create', array($this, 'on_user_create'));
        $this->add_hook('identity_create', array($this, 'on_identity_create'));
    }

    public function on_user_create($params){
        $this->write_log("hooked user_create", $params);
        $this->attr_username = strtolower(idn_to_utf8($params['user']));
        if(!$this->is_data_ready) $this->load_ldap_data();
        if ($this->is_data_ready) {
            $params['user_name']  = $this->attr_username;
            $params['user_email'] = $this->attr_email;
        }

        return $params;
    }

    public function on_identity_create($params){
        $this->write_log("hooked identity_create", $params);
        if(!$this->is_data_ready) $this->load_ldap_data();
        if(isset($params['login']) && $params['login']===true){
            $this->write_log("identity creation on login, dn pushed to " . $this->attr_dn);
            $params['record']['name'] = $this->attr_dn;
        }
        return $params;
    }
    
    private function load_ldap_data(){
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
                $this->ldap = null;
                return false;
            };

        };

        $found = $this->ldap->search(
            $this->ldap_config['base_dn'],
            "(&(mail=*)(objectClass=user)(samAccountName=" . $this->attr_username . ")(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            'sub',
            array('distinguishedName','samAccountName','mail','displayName')
        );


        if(FALSE === $found){
            $this->is_data_ready = false;
            return false;
        }

        foreach($found->entries(true) as $dn=>$attr){
            $this->attr_username = $attr['samaacountname'];
            $this->attr_email = $attr['mail'];
            $this->attr_dn = $attr['displayname'];
            $this->is_data_ready = true;
            break;
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