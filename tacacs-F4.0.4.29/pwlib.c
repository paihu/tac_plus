/*
 * $Id: pwlib.c,v 1.25 2009-03-17 18:40:20 heas Exp $
 *
 * Copyright (c) 1995-1998 by Cisco systems, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that this
 * copyright and permission notice appear on all copies of the
 * software and supporting documentation, the name of Cisco Systems,
 * Inc. not be used in advertising or publicity pertaining to
 * distribution of the program without specific prior permission, and
 * notice be given in supporting documentation that modification,
 * copying and distribution is by permission of Cisco Systems, Inc.
 *
 * Cisco Systems, Inc. makes no representations about the suitability
 * of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "tac_plus.h"
#include "expire.h"

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif

#ifdef SHADOW_PASSWORDS
# include <shadow.h>
#endif

#if HAVE_PAM
# ifdef __APPLE__	/* MacOS X */
#  if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1060
#   include <security/pam_appl.h>
#  else
#   include <pam/pam_appl.h>
#  endif
# else
#  include <security/pam_appl.h>
# endif
static int pam_tacacs(int, const struct pam_message **, struct pam_response **,
		      void *);
#endif

/*
 * Generic password verification routines for des, file and cleartext passwords
 */
static int etc_passwd_file_verify(char *, char *, struct authen_data *);
static int des_verify(char *, char *);
#if HAVE_PAM
static int pam_verify(char *, char *);
#endif
static int passwd_file_verify(char *, char *, struct authen_data *, char *);

extern char *progname;

/* Adjust data->status depending on whether a user has expired or not */
void
set_expiration_status(char *exp_date, struct authen_data *data)
{
    int expired;

    /* if the status is anything except pass, there's no point proceeding */
    if (data->status != TAC_PLUS_AUTHEN_STATUS_PASS) {
	return;
    }

    /*
     * Check the expiration date, if any. If NULL, this check will return
     * PW_OK
     */
    expired = check_expiration(exp_date);

    switch (expired) {
    case PW_OK:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password has not expired %s",
		   exp_date ? exp_date : "<no expiry date set>");

	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	break;

    case PW_EXPIRING:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password will expire soon %s",
		   exp_date ? exp_date : "<no expiry date set>");
	if (data->server_msg)
	    free(data->server_msg);
	data->server_msg = tac_strdup("Password will expire soon");
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	break;

    case PW_EXPIRED:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password has expired %s",
		   exp_date ? exp_date : "<no expiry date set>");
	if (data->server_msg)
	    free(data->server_msg);
	data->server_msg = tac_strdup("Password has expired");
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	break;

    default:
	report(LOG_ERR, "%s: Bogus return value %d from check_expiration",
	       session.peer, expired);
	data->status = TAC_PLUS_AUTHEN_STATUS_ERROR;
	break;
    }

    return;
}

/*
 * Verify that this user/password is valid.  Works only for cleartext, file,
 * PAM LDAP and des passwords.  Return 1 if password is valid.
 */
int
verify(char *name, char *passwd, struct authen_data *data, int recurse)
{
    char *exp_date;
    char *cfg_passwd;
    char *p;

    if (data->type == TAC_PLUS_AUTHEN_TYPE_PAP) {
	cfg_passwd = cfg_get_pap_secret(name, recurse);
    } else {
	cfg_passwd = cfg_get_login_secret(name, recurse);
    }

    /*
     * If there is no login or pap password for this user, see if there is
     * a global password that can be used.
     */
    if (cfg_passwd == NULL) {
	cfg_passwd = cfg_get_global_secret(name, recurse);
    }

    /*
     * If we still have no password for this user (or no user for that
     * matter) but the default authentication = file <file> statement
     * has been issued, attempt to use this password file
     */
    if (cfg_passwd == NULL) {
        if (default_authen_type == TAC_PLUS_DEFAULT_AUTHEN_TYPE_FILE) {
	    char *file = cfg_get_authen_default();
	    report(LOG_DEBUG, "verify user: %s pwfile: %s",name,file);
	    if (file) {
	        return(passwd_file_verify(name, passwd, data, file));
	    }
#if HAVE_PAM
        } else if (default_authen_type == TAC_PLUS_DEFAULT_AUTHEN_TYPE_PAM) {
	    /* try to verify the password via PAM */
	    if (!pam_verify(name, passwd)) {
	       data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	       return(0);
	    } else
               data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

	    exp_date = cfg_get_expires(name, recurse);
	    set_expiration_status(exp_date, data);
	    return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
#endif        
        }

	/* otherwise, we fail */
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    }

    /* We have a configured password. Deal with it depending on its type */
#if HAVE_PAM
    if (strcmp(cfg_passwd, "PAM") == 0) {
	/* try to verify the password via PAM */
	if (!pam_verify(name, passwd)) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

	exp_date = cfg_get_expires(name, recurse);
	set_expiration_status(exp_date, data);
	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }
#endif    

#if HAVE_LDAP
    if (strcmp(cfg_passwd, "ldap") == 0) {
	/* try to verify the password via LDAP */
	if (ldap_verify(name,passwd)!=TAC_PLUS_AUTHEN_STATUS_PASS) {
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Ldap Password is incorrect");
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Ldap Password is correct");
	}
	
	exp_date = cfg_get_expires(name, recurse);
	set_expiration_status(exp_date, data);
	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }
#endif    

    p = tac_find_substring("cleartext ", cfg_passwd);
    if (p != NULL) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "verify daemon %s == NAS %s", p, passwd);

	if (strcmp(passwd, p)) {
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is incorrect");
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is correct");
	}

	exp_date = cfg_get_expires(name, recurse);
	set_expiration_status(exp_date, data);
	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("des ", cfg_passwd);
    if (p) {
	/* try to verify this des password */
	if (!des_verify(passwd, p)) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	}

	exp_date = cfg_get_expires(name, recurse);
	set_expiration_status(exp_date, data);
	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("file ", cfg_passwd);
    if (p) {
	return(passwd_file_verify(name, passwd, data, p));
    }

    /*
     * Oops. No idea what kind of password this is. This should never
     * happen as the parser should never create such passwords.
     */
    report(LOG_ERR, "%s: Error cannot identify password type %s for %s",
	   session.peer,
	   cfg_passwd && cfg_passwd[0] ? cfg_passwd : "<NULL>",
	   name ? name : "<unknown>");

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    return(0);
}

/*
 * Verify that this user/password is valid for the matching password data,
 * such as "cleartext foopwd".  Works only for cleartext, des and file
 * passwords and is used only for or by enable().
 * Return 1 if password is valid.  The caller needs to check any expiration
 * dates itself.
 */
int
verify_pwd(char *username, char *passwd, struct authen_data *data,
	   char *cfg_passwd)
{
    char *p;

    /* Deal with the cfg_passwd depending on its type */
    p = tac_find_substring("cleartext ", cfg_passwd);
    if (p) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "verify daemon %s == NAS %s", p, passwd);

	if (strcmp(passwd, p)) {
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is incorrect");
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;

	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "Password is correct");
	}

	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("des ", cfg_passwd);
    if (p) {
	/* try to verify this des password */
	if (!des_verify(passwd, p)) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	}

	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    p = tac_find_substring("file ", cfg_passwd);
    if (p) {
	if (!passwd_file_verify(username, passwd, data, p)) {
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	} else {
	    data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
	}

	return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
    }

    /* Oops. No idea what kind of password this is. This should never
     * happen as the parser should never create such passwords.
     */
    report(LOG_ERR, "%s: Error cannot identify password type %s for %s",
	   session.peer,
	   cfg_passwd && cfg_passwd[0] ? cfg_passwd : "<NULL>",
	   username ? username : "<unknown>");

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    return(0);
}

/* verify that this user/password is valid per /etc/passwd.  Return 0 if
 * invalid.
 */
static int
etc_passwd_file_verify(char *user, char *supplied_passwd,
		       struct authen_data *data)
{
    struct passwd *pw;
    char *exp_date;
    char *cfg_passwd;
#ifdef SHADOW_PASSWORDS
    char buf[12];
#endif /* SHADOW_PASSWORDS */

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;

    setpwent();
    pw = getpwnam(user);
    endpwent();

    if (pw == NULL) {
	/* no entry exists */
	return(0);
    }

    if (*pw->pw_passwd == '\0' ||
	supplied_passwd == NULL ||
	*supplied_passwd == '\0') {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    }
    cfg_passwd = pw->pw_passwd;
    exp_date = pw->pw_shell;

#ifdef SHADOW_PASSWORDS
    if (STREQ(pw->pw_passwd, "x")) {
	struct spwd *spwd = getspnam(user);

	if (!spwd) {
	    if (debug & DEBUG_PASSWD_FLAG) {
		report(LOG_DEBUG, "No entry for %s in shadow file", user);
	    }
	    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    return(0);
	}
	if (debug & DEBUG_PASSWD_FLAG) {
	    report(LOG_DEBUG, "Found entry for %s in shadow file", user);
	}
	cfg_passwd = spwd->sp_pwdp;

	/*
	 * Sigh. The Solaris shadow password file contains its own
	 * expiry date as the number of days after the epoch
	 * (January 1, 1970) when the password expires.
	 * Convert this to ascii so that the traditional tacacs
	 * password expiration routines work correctly.
	 */
	if (spwd->sp_expire > 0) {
	    long secs = spwd->sp_expire * 24 * 60 * 60;
	    char *p = ctime(&secs);

	    memcpy(buf, p + 4, 7);
	    memcpy(buf + 7, p + 20, 4);
	    buf[11] = '\0';
	    exp_date = buf;
	}
    }
#endif /* SHADOW_PASSWORDS */

    /* try to verify the password */
    if (!des_verify(supplied_passwd, cfg_passwd)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

    /* password ok. Check expiry field */
    set_expiration_status(exp_date, data);

    return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
}

/*
 * verify that this user/password is valid per a passwd(5) style database.
 * Return 0 if invalid.
 */
static int
passwd_file_verify(char *user, char *supplied_passwd, struct authen_data *data,
		   char *filename)
{
    struct passwd *pw;
    char *exp_date;
    char *cfg_passwd;

    data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
    
    if (filename && STREQ(filename, "/etc/passwd")) {
	return(etc_passwd_file_verify(user, supplied_passwd, data));
    }

    /* an alternate filename */
    if (!(access(filename, R_OK) == 0)) {
	report(LOG_ERR, "%s %s: Cannot access %s for user %s -- %s",
	       session.peer, session.port, filename, user, strerror(errno));
	return(0);
    }

    pw = tac_passwd_lookup(user, filename);

    if (pw == NULL)
	/* no entry exists */
	return(0);

    if (*pw->pw_passwd == '\0' ||
	supplied_passwd == NULL ||
	*supplied_passwd == '\0') {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    }
    cfg_passwd = pw->pw_passwd;
    exp_date = pw->pw_shell;

    /* try to verify the password */
    if (!des_verify(supplied_passwd, cfg_passwd)) {
	data->status = TAC_PLUS_AUTHEN_STATUS_FAIL;
	return(0);
    } else {
	data->status = TAC_PLUS_AUTHEN_STATUS_PASS;
    }

    /* password ok. Check expiry field */
    set_expiration_status(exp_date, data);
    return(data->status == TAC_PLUS_AUTHEN_STATUS_PASS);
}

/*
 * verify a provided password against a des encrypted one.  return 1 if
 * verified, 0 otherwise.
 */
static int
des_verify(char *users_passwd, char *encrypted_passwd)
{
    char *ep;

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "verify %s %s", users_passwd, encrypted_passwd);

    if (users_passwd == NULL ||
	*users_passwd == '\0' ||
	encrypted_passwd == NULL ||
	*encrypted_passwd == '\0') {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "verify returns 0");
	return(0);
    }

    ep = (char *)crypt(users_passwd, encrypted_passwd);

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "%s encrypts to %s", users_passwd, ep);

    if (strcmp(ep, encrypted_passwd) == 0) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password is correct");
	return(1);
    }

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "Password is incorrect");

    return(0);
}

#if HAVE_PAM
/* pam_conv (PAM conversation) callback */
static int
pam_tacacs(int nmsg, const struct pam_message **pmpp, struct pam_response
	   **prpp, void *appdata_ptr)
{
    int i;
    struct authen_cont *acp;
    char *passwd = (char *)appdata_ptr;
    u_char *reply, *rp;

    if (debug & DEBUG_PASSWD_FLAG)
	report(LOG_DEBUG, "pam_tacacs received %d pam_messages", nmsg);

    if (nmsg <= 0 || nmsg > PAM_MAX_NUM_MSG)
	return(PAM_CONV_ERR);
    if ((*prpp = (struct pam_response *)
		 tac_malloc(nmsg * sizeof(struct pam_response))) == NULL)
	return(PAM_BUF_ERR);
    memset((struct pam_repsonse *)*prpp, 0,
	   nmsg * sizeof(struct pam_response));

    for (i = 0; i < nmsg; ++i) {
	switch (pmpp[i]->msg_style) {
	case PAM_PROMPT_ECHO_OFF:
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "%s %s: PAM_PROMPT_ECHO_OFF", session.peer,
		       session.port);

	    /* pre-supplied password, such as service=PAP, or prompt for it */
	    if (passwd != NULL && strlen(passwd) > 0) {
		prpp[i]->resp = tac_strdup(passwd);
	    } else {	        
		send_authen_reply(TAC_PLUS_AUTHEN_STATUS_GETPASS,
				  (char *)pmpp[i]->msg,
				  pmpp[i]->msg ? strlen(pmpp[i]->msg) : 0,
				  NULL, 0, TAC_PLUS_AUTHEN_FLAG_NOECHO);
		reply = get_authen_continue();
		if (!reply) {
		    /* Typically due to a premature connection close */
		    report(LOG_ERR, "%s %s: Null reply packet, expecting "
			   "CONTINUE", session.peer, session.port);
 		    goto fail;
		}
		acp = (struct authen_cont *)(reply + TAC_PLUS_HDR_SIZE);

		rp = reply + TAC_PLUS_HDR_SIZE +
		     TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;
		/*
		 * A response to our GETDATA/GETPASS request. Create a
		 * null-terminated string for authen_data.
		 */
		prpp[i]->resp = (char *)tac_malloc(acp->user_msg_len + 1);
		memcpy(prpp[i]->resp, rp, acp->user_msg_len);
		prpp[i]->resp[acp->user_msg_len] = '\0';
		free(reply);
	    }
	    break;
	case PAM_PROMPT_ECHO_ON:
	    if (debug & DEBUG_PASSWD_FLAG)
		report(LOG_DEBUG, "%s %s: PAM_PROMPT_ECHO_ON", session.peer,
		       session.port);

	    send_authen_reply(TAC_PLUS_AUTHEN_STATUS_GETDATA,
			      (char *)pmpp[i]->msg,
			      pmpp[i]->msg ? strlen(pmpp[i]->msg) : 0,
			      NULL, 0, 0);
	    reply = get_authen_continue();
	    if (!reply) {
		/* Typically due to a premature connection close */
		report(LOG_ERR, "%s %s: Null reply packet, expecting CONTINUE",
		       session.peer, session.port);
 		goto fail;
	    }
	    acp = (struct authen_cont *)(reply + TAC_PLUS_HDR_SIZE);

	    rp = reply + TAC_PLUS_HDR_SIZE + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;
	    /*
	     * A response to our GETDATA/GETPASS request. Create a
	     * null-terminated string for authen_data.
	     */
	    prpp[i]->resp = (char *)tac_malloc(acp->user_msg_len + 1);
	    memcpy(prpp[i]->resp, rp, acp->user_msg_len);
	    prpp[i]->resp[acp->user_msg_len] = '\0';

	    free(reply);
	    break;
	case PAM_ERROR_MSG:
	    send_authen_error((char *)pmpp[i]->msg);
	    break;
	case PAM_TEXT_INFO:
#ifdef PAM_MSG_NOCONF
	case PAM_MSG_NOCONF:
#endif
	    /* so we should not receive these with PAM_SILENT set */
	    break;
#ifdef PAM_CONV_INTERRUPT
	case PAM_CONV_INTERRUPT:
	    return(PAM_SUCCESS);
#endif
	default:
	    report(LOG_ERR, "%s %s: unknown pam_conv message type %d",
		   session.peer, session.port, pmpp[i]->msg_style);
	    goto fail;
	}
    }

    return(PAM_SUCCESS);
fail:
    for (i = 0; i < nmsg; ++i) {
	if ((*prpp)[i].resp != NULL) {
	    memset((*prpp)[i].resp, 0, strlen((*prpp)[i].resp));
	    free((*prpp)[i].resp);
	}
    }
    memset(*prpp, 0, nmsg * sizeof(struct pam_response));
    free(*prpp);
    *prpp = NULL;
    return(PAM_CONV_ERR);
}

/*
 * verify a provided user/password via PAM.
 * return 1 if verified, 0 otherwise.
 */
static int
pam_verify(char *user, char *passwd)
{
    int			err;
    int			pam_flag;
    struct pam_conv	conv = { pam_tacacs, passwd };
    pam_handle_t	*pamh = NULL;

    if (user == NULL /* XXX || passwd == NULL || *passwd == '\0'*/) {
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "pam_verify returns 0");
	return(0);
    }

    if ((err = pam_start(progname, user, &conv, &pamh)) != PAM_SUCCESS) {
	report(LOG_ERR, "pam_start failed: %s", pam_strerror(pamh, err));
	pam_end(pamh, err);
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "pam_verify returns 0");
	return(0);
    }

    /* don't ignore PAM messages if password debugging is on */
    pam_flag = (debug & DEBUG_PASSWD_FLAG) ? 0 : PAM_SILENT;

    switch ((err = pam_authenticate(pamh, pam_flag))) {
    case PAM_SUCCESS:
	pam_end(pamh, err);
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "pam_verify returns 1");
	return(1);
	break;
    case PAM_USER_UNKNOWN:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Unknown user");
	break;
    case PAM_AUTH_ERR:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "Password is incorrect");
	break;
    default:
	if (debug & DEBUG_PASSWD_FLAG)
	    report(LOG_DEBUG, "pam_authenticate() returned unknown value %d",
		   err);
	break;
    }

    pam_end(pamh, err);
    return(0);
}
#endif

#ifdef HAVE_LDAP
int ldap_init(LDAP **ldap,char *username,char *password) {

    int auth_method     = LDAP_AUTH_SIMPLE;
    int desired_version = LDAP_VERSION3;
    
    struct berval cred;
    struct berval *servcred;
  
    if (debug & DEBUG_LDAP_FLAG)
       report(LOG_DEBUG,"ldap initialize");

    if (ldap_initialize(ldap,session.ldap_url)!=LDAP_SUCCESS) {
       report(LOG_ERR,"ldap_initialize failed");
       return(LDAP_OPERATIONS_ERROR);
    }

    int ret=ldap_set_option(*ldap, LDAP_OPT_PROTOCOL_VERSION, &desired_version);
    if (ret) {
      report(LOG_ERR,"ldap_set_option %s",ldap_err2string(ret));
      return(ret);
    }
 
    cred.bv_val=password;
    cred.bv_len = strlen(password);
    
    if (debug & DEBUG_LDAP_FLAG)
       report(LOG_DEBUG,"ldap user dn: %s",username);
 
    ret=ldap_sasl_bind_s(*ldap,username,LDAP_SASL_SIMPLE,&cred,NULL,NULL,&servcred);
    if (ret) {
      report(LOG_ERR,"ldap_sasl_bind_s %s (%d) user: %s",ldap_err2string(ret),ret,username);
      if (debug & DEBUG_LDAP_FLAG)
         report(LOG_DEBUG,"ldap_sasl_bind_s %s (%d)",ldap_err2string(ret),ret);
    } else {    
       if (debug & DEBUG_LDAP_FLAG)
          report(LOG_DEBUG,"ldap successful bind to %s",session.ldap_url);
    }   
    return(ret);   

}

void ldap_close(LDAP *ldap) {
     if (debug & DEBUG_LDAP_FLAG)
        report(LOG_DEBUG,"ldap unbind from: %s",session.ldap_url);
     int ret = ldap_unbind_ext_s(ldap,NULL,NULL);
     if (ret)
        report(LOG_ERR, "ldap_unbind_s: %s", ldap_err2string(ret));
}

int ldap_get_group(LDAP *ldap,char *name) {
    int retvalue=TAC_PLUS_AUTHEN_STATUS_FAIL;
    char *member=ldap_search(ldap,name);
    if (member) {
       /* check if group exists in config */
       if (cfg_group_exists(member)) {
          update_config(name,member);
          retvalue=TAC_PLUS_AUTHEN_STATUS_PASS;
       } else {
          if (debug & DEBUG_LDAP_FLAG)
             report(LOG_DEBUG,"ldap group %s for user %s not found in tacacs config",member,name);
          report(LOG_ERR,"ldap group %s for user %s not found in tacacs config",member,name);
       }
       free(member);        
    } 
    return (retvalue);
}

int ldap_verify(char *name,char *password) {
    int retvalue=TAC_PLUS_AUTHEN_STATUS_FAIL;
    LDAP *ldap;    
    char *user_prefix="uid=";

    if (debug & DEBUG_LDAP_FLAG)
       report(LOG_DEBUG,"ldap_verify start user: %s password: %s",name,password);
    
    /* ldap username format: uid=username,ldap_user_base_dn; */
    int new_len=strlen(session.ldap_user_base_dn)+strlen(name)+strlen(user_prefix)+2;
    char *ldap_username=tac_malloc(new_len);
    memset(ldap_username, 0, new_len);
    strncat(ldap_username,user_prefix,strlen(user_prefix));
    strncat(ldap_username,name,strlen(name));
    strncat(ldap_username,",",strlen(","));
    strncat(ldap_username,session.ldap_user_base_dn,strlen(session.ldap_user_base_dn));
    
    if (ldap_init(&ldap,ldap_username,password)==LDAP_SUCCESS) {
       retvalue=ldap_get_group(ldap,name);
    }
    ldap_close(ldap);
    free(ldap_username);    
    if (debug & DEBUG_LDAP_FLAG)
             report(LOG_DEBUG,"ldap_verify return value: %d",retvalue);
    return (retvalue);
}

char* ldap_search(LDAP *ldap,char *name) {
      BerElement* ber;
      LDAPMessage* msg;
      LDAPMessage* entry;
      char *group=NULL;
      char *attr;
      struct berval **vals;
      int sizelimit=10;
      char *attrs[]={"cn",NULL};
      int ldap_search_timeout=3;
      struct timeval search_timeout;
      memset(&search_timeout, 0, sizeof(struct timeval));
      search_timeout.tv_sec=ldap_search_timeout;
      
      /* ldap filter format: (memberUid=name) */
      char *filter1="(memberUid=";
      int new_len=strlen(filter1)+strlen(name)+2;
      char *filter=malloc(new_len);
      memset(filter, 0, new_len);
      strncat(filter,filter1,strlen(filter1));
      strncat(filter,name,strlen(name));
      strncat(filter,")",strlen(")"));
      
      if (debug & DEBUG_LDAP_FLAG)
         report(LOG_DEBUG, "ldap_search for group filter: %s",filter);
      int ret=ldap_search_ext_s(ldap,session.ldap_group_base_dn,LDAP_SCOPE_SUBTREE,filter,attrs,0,NULL,NULL,&search_timeout,sizelimit,&msg);
      if (ret) {
         report(LOG_ERR,"ldap_search_ext_s %s",ldap_err2string(ret));
         return NULL;
      }
      if (debug & DEBUG_LDAP_FLAG)
	 report(LOG_DEBUG,"ldap_search_ext_s %s",ldap_err2string(ret));	 
  
      if (ldap_count_entries(ldap, msg)==1) {
         entry = ldap_first_entry(ldap, msg);
         if (entry!=NULL) {
            attr = ldap_first_attribute(ldap, entry, &ber);
            if (attr != NULL) {
               vals = ldap_get_values_len(ldap, entry, attr);
               if (vals!=NULL) {
                  if (ldap_count_values_len(vals)==1) {
                     group=malloc(vals[0]->bv_len+1);
                     memset(group,0,vals[0]->bv_len+1);
                     strncpy(group,vals[0]->bv_val,vals[0]->bv_len);
                  }
                  ldap_value_free_len(vals);
               }               
               ldap_memfree(attr);
            }
            if (ber != NULL)
               ber_free(ber,0);
         }        
      } else {
         if (ldap_count_entries(ldap, msg)==0) {
            if (debug & DEBUG_LDAP_FLAG)
               report(LOG_DEBUG,"user %s is not member of any tacacs group",name);
	     report(LOG_ERR,"user %s is not member of any tacacs group",name);
         } else {
            if (debug & DEBUG_LDAP_FLAG)
	       report(LOG_DEBUG,"user %s is member of more than one(%d) group",name,ldap_count_entries(ldap, msg));
	    report(LOG_ERR,"user %s is member of more than one(%d) group",name,ldap_count_entries(ldap, msg));   
         }
      }
      ldap_msgfree(msg);
      free(filter);
      if (debug & DEBUG_LDAP_FLAG)
	 report(LOG_DEBUG,"ldap_search name: %s group: %s",name,group);	 
      return (group);
}

#endif
