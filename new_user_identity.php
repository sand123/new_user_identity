<?php
/**
 * New user identity
 *
 * Populates a new user's default identity from LDAP on their first visit.
 *
 * This plugin requires that a working public_ldap directory be configured.
 *
 * @version @package_version@
 * @author Kris Steinhoff
 * @license GNU GPLv3+
 */
class new_user_identity extends rcube_plugin
{
    public $task = 'login';

    private $rc;
    private $ldap;
    private $log_file;

    function init()
    {
        $this->rc = rcmail::get_instance();
        $this->log_file = 'new_user_identity_debug.log';

        $this->add_hook('user_create', array($this, 'lookup_user_name'));
        $this->add_hook('login_after', array($this, 'login_after'));
    }

    function lookup_user_name($args)
    {
        $this->write_log("hooked user_create args", $args);
        if ($this->init_ldap($args['host'])) {
            $results = $this->ldap->search('*', idn_to_utf8($args['user']), true);

            if (count($results->records) == 1) {
                $user_name  = is_array($results->records[0]['name']) ? $results->records[0]['name'][0] : $results->records[0]['name'];
                $user_email = is_array($results->records[0]['email']) ? $results->records[0]['email'][0] : $results->records[0]['email'];

                $args['user_name']  = $user_name;
                $args['email_list'] = array();

                if (!$args['user_email'] && strpos($user_email, '@')) {
                    $args['user_email'] = rcube_utils::idn_to_ascii($user_email);
                }

                foreach (array_keys($results[0]) as $key) {
                    if (!preg_match('/^email($|:)/', $key)) {
                        continue;
                    }

                    foreach ((array) $results->records[0][$key] as $alias) {
                        if (strpos($alias, '@')) {
                            $args['email_list'][] = rcube_utils::idn_to_ascii($alias);
                        }
                    }
                }

            }
        }

        return $args;
    }

    function login_after($args)
    {
        $this->load_config();

        if ($this->ldap || !$this->rc->config->get('new_user_identity_onlogin')) {
            return $args;
        }

        $identities = $this->rc->user->list_emails();
        $ldap_entry = $this->lookup_user_name(array(
                'user' => $this->rc->user->data['username'],
                'host' => $this->rc->user->data['mail_host'],
        ));

        foreach ((array) $ldap_entry['email_list'] as $email) {
            foreach ($identities as $identity) {
                if ($identity['email'] == $email) {
                    continue 2;
                }
            }

            $plugin = $this->rc->plugins->exec_hook('identity_create', array(
                'login'  => true,
                'record' => array(
                    'user_id'  => $this->rc->user->ID,
                    'standard' => 0,
                    'email'    => $email,
                    'name'     => $ldap_entry['user_name']
                ),
            ));

            if (!$plugin['abort'] && $plugin['record']['email']) {
                $this->rc->user->insert_identity($plugin['record']);
            }
        }
        return $args;
    }

    private function init_ldap($host)
    {
        if ($this->ldap) {
            $this->write_log("LDAP backedn already initialized");
            return $this->ldap->ready;
        }

        $this->load_config();

        $addressbook = $this->rc->config->get('new_user_identity_addressbook');
        $ldap_config = (array)$this->rc->config->get('ldap_public');
        $match       = $this->rc->config->get('new_user_identity_match');

        if (empty($addressbook) || empty($match) || empty($ldap_config[$addressbook])) {
            $this->write_log("LDAP init failed");
            return false;
        }

        $this->write_log("initialize ldap backend with params", array(
            "addrbook"=>$addressbook,
            "match"=>$match,
            "mail_domain"=>$this->rc->config->mail_domain($host)
        ));

        $this->ldap = new new_user_identity_ldap_backend(
            $ldap_config[$addressbook],
            $this->rc->config->get('ldap_debug'),
            $this->rc->config->mail_domain($host),
            $match);

        return $this->ldap->ready;
    }

    private function write_log($msg, $data = array()){
        if(is_null($this->log_file)) return;
        $this->rc->write_log($this->log_file, $msg . "\r\n" . var_export($data, true));
    }
}

class new_user_identity_ldap_backend extends rcube_ldap
{
    function __construct($p, $debug, $mail_domain, $search)
    {
        parent::__construct($p, $debug, $mail_domain);
        $this->prop['search_fields'] = (array)$search;
    }
}
