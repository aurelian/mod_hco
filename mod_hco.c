/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
**  mod_hco.c -- Apache sample hco module
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory
**  by running:
**
**    $ apxs -c -i mod_hco.c
**
*/

#include "apr.h"
#include "apr_version.h"
#include "apr_strings.h"

#include "ap_config.h"

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_vhost.h"

#include <curl/curl.h>
#include <time.h>

#define HCO_DISABLED             0
#define HCO_ENABLED              1

#define hco_get_server_conf(srv) (hco_server_conf *)ap_get_module_config(srv->module_config, &hco_module)

module AP_MODULE_DECLARE_DATA hco_module;

enum strategy {
  HCO_STRATEGY_ALLOW,
  HCO_STRATEGY_PASS,
  HCO_STRATEGY_DENY
};

typedef struct {
    // resources
    CURL *curl;
    // configurations
    const char *base_path;
    const char *end_point;
    const char *auth_key;
    enum strategy auth_strategy;
    int enabled;
} hco_server_conf;

typedef struct {
    const char *app_id;
} hco_req_conf;

/* _______________________________________
**
** Utilities
** _______________________________________
*/

/*
 * Returns a table with app_id and app_key value keys.
 */
static apr_table_t *
parse_query_string(apr_pool_t *pool, const char *query)
{
    char *next;
    char *last;
    char *query_copy;
    apr_table_t *table;

    table = apr_table_make (pool, 1);

    if (!query) {
        return table;
    }

    // because of the destructive nature of apr_strtok,
    // we need to make a copy of the query string
    // use the request pool so we can get free for free
    query_copy = apr_pstrndup(pool, query, strlen(query));

    next = (char *) apr_strtok( query_copy, "&", &last );
    while (next) {
        apr_collapse_spaces(next, next);
        char *key;
        char *value;
        key =  (char *) apr_strtok( next, "=", &value);
        if(key && (strcmp(key, "app_key")  == 0 || strcmp(key, "app_id" ) == 0)) {
            apr_table_set(table, key, value);
        }
        next = (char*) apr_strtok(NULL, "&", &last);
    }
    return table;
}

struct RemoteMemoryStruct {
  char *memory;
  size_t size;
};

static size_t hco_remote_write_data(void *buffer, size_t size, size_t nmemb, void *data)
{
    size_t realsize = size * nmemb;
    struct RemoteMemoryStruct *mem = (struct RemoteMemoryStruct *)data;
    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory) {
      // handle out-of-memory.
      memcpy(&(mem->memory[mem->size]), buffer, realsize);
      mem->size += realsize;
      mem->memory[mem->size] = 0;
    }
    return realsize;
}

/* _______________________________________
**
** Hook chain
** _______________________________________
*/

/*
 * If we're activated, pass the request to the hco_handler
 */
static int hco_fixups(request_rec *r)
{
    hco_server_conf *sconf = hco_get_server_conf(r->server);

    if(!sconf->enabled
        || strstr(r->uri, sconf->base_path) == NULL
        || sconf->auth_strategy == HCO_STRATEGY_ALLOW)
    {
        return OK;
    }

    r->handler = "hco-handler";
    return OK;
}

/*
 * this makes the auth request and adds a header
 */
static void pass_strategy(CURL *curl, request_rec *r)
{
    int remote_code;
    CURLcode res;
    res = curl_easy_perform(curl);

    if(CURLE_OK != res) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "HCO: remote-> < %s >.", curl_easy_strerror(res));
        apr_table_set(r->headers_out, "X-HcoAuthResponse", "-1");
        return;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &remote_code);
    apr_table_set(r->headers_out, "X-HcoAuthResponse", apr_itoa(r->pool, remote_code));
    return;
}

/*
 * this makes the auth request and forwards the upstream response in case of failure
 */
static int deny_strategy(CURL *curl, request_rec *r)
{
    int remote_code;
    char *remote_content_type;
    struct RemoteMemoryStruct chunk;
    CURLcode res;

    chunk.memory= malloc(1);
    chunk.size  = 0;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, hco_remote_write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);

    if(CURLE_OK != res) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "HCO: remote-> < %s >.", curl_easy_strerror(res));
        return OK;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &remote_code);
    if(remote_code == 200) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "HCO: handler-> done.");
        return DECLINED;
    }

    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &remote_content_type);
    r->content_type= remote_content_type;

    ap_rputs(chunk.memory, r);
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "HCO: handler-> forward %d- %s.", remote_code, remote_content_type);

    return OK; // remote_code;
}


/*
 * The hco content handler
 */
static int hco_handler(request_rec *r) {
    const char *authpath;
    const char *app_id;
    const char *app_key;
    apr_table_t *params;

    hco_req_conf *rconf;
    hco_server_conf * sconf;

    if(strcmp(r->handler, "hco-handler")) {
        return DECLINED;
    }

    // parse query args and extract app_id and maybe app_key
    params = parse_query_string(r->pool, r->parsed_uri.query);
    app_id = apr_table_get(params, "app_id");
    app_key= apr_table_get(params, "app_key");

    // save app_id for later use in the hook chain
    rconf = apr_palloc(r->pool, sizeof(hco_req_conf));
    ap_set_module_config(r->request_config, &hco_module, rconf);
    rconf->app_id = app_id;

    sconf= hco_get_server_conf(r->server);
    authpath = apr_pstrcat(
        r->pool,
        sconf->end_point,
        "/transactions/authorize.xml?app_id=",
        (app_id==NULL)? "" : app_id, // app_id is mandatory.
        (app_key==NULL)? "" : apr_pstrcat(r->pool, "&app_key=", app_key, NULL), // app_key is not
        "&provider_key=",
        sconf->auth_key,
        NULL
    );
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "HCO: handler-> ready: <%s>.", authpath);
    curl_easy_setopt(sconf->curl, CURLOPT_URL, authpath);

    if(sconf->auth_strategy == HCO_STRATEGY_PASS) {
        pass_strategy(sconf->curl, r);
        return DECLINED;
    } else if(sconf->auth_strategy == HCO_STRATEGY_DENY) {
        return deny_strategy(sconf->curl, r);
    }
    return DECLINED;
}

/*
 * Reports the transaction.
 */
static int
hco_log_transaction(request_rec *r)
{
    const char *report_path;
    const char *post_data;
    CURLcode res;

    hco_req_conf *rconf = ap_get_module_config(r->request_config, &hco_module);
    hco_server_conf *sconf = hco_get_server_conf(r->server);

    if(!sconf->enabled || strstr(r->uri, sconf->base_path) == NULL) {
        return OK;
    }

    if(rconf->app_id == NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "HCO: log-> skip report missing app_id arg.");
        return OK;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "HCO: log-> sending report.");

    report_path= apr_pstrcat(r->pool, sconf->end_point, "/transactions.xml", NULL);

    post_data= apr_pstrcat(
        r->pool,
        "provider_key=",
        sconf->auth_key,
        "&transactions[0][app_id]=",
        rconf->app_id,
        "&transactions[0][usage][hits]=1",
        NULL
    );

    curl_easy_setopt(sconf->curl, CURLOPT_URL, report_path);
    curl_easy_setopt(sconf->curl, CURLOPT_POSTFIELDS, post_data);

#if 1
// XXX. replace with debug.
    curl_easy_setopt(sconf->curl, CURLOPT_WRITEFUNCTION, hco_remote_write_data);
    struct RemoteMemoryStruct chunk;
    chunk.memory= malloc(1);
    chunk.size  = 0;
    curl_easy_setopt(sconf->curl, CURLOPT_WRITEDATA, (void *)&chunk);
#endif

    res= curl_easy_perform(sconf->curl);

    if(CURLE_OK == res) {
#if 1
// XXX. replace with debug.
      if(chunk.memory) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "HCO: log-> transaction response: < %s >.", chunk.memory );
        free(chunk.memory);
      }
#endif
    } else {
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "HCO: log-> failed: < %s >.", curl_easy_strerror(res));
    }
    return OK;
}



/* _______________________________________
**
** Module Configuration
** _______________________________________
*/

/*
 * Config: HcoEngine On|Off
 */
static const char *cmd_hco_engine(cmd_parms *cmd, void *dconf, int flag)
{
    hco_server_conf *sconf = hco_get_server_conf(cmd->server);

    sconf->enabled = (flag ? HCO_ENABLED : HCO_DISABLED);
    return NULL;
}

/*
 * Config: HcoBasePath "/path"
 */
static const char *cmd_hco_base_path(cmd_parms *cmd, void *dconf, const char *a1) {
    hco_server_conf *sconf = hco_get_server_conf(cmd->server);

    sconf->base_path = a1;
    return NULL;
}

/*
 * Config: HcoEndPoint "url"
 */
static const char *cmd_hco_end_point(cmd_parms *cmd, void *dconf, const char *a1)
{
    hco_server_conf *sconf = hco_get_server_conf(cmd->server);

    sconf->end_point= a1;
    return NULL;
}

/*
 * Config HcoAuthCode "codeffaap20192"
 */
static const char *cmd_hco_auth_key(cmd_parms *cmd, void *dconf, const char *a1)
{
    hco_server_conf *sconf = hco_get_server_conf(cmd->server);

    sconf->auth_key= a1;
    return NULL;
}

/*
 * Config: HcoAuthStrategy "allow|pass|deny"
 */
static const char *cmd_hco_auth_strategy(cmd_parms *cmd, void *dconf, const char *a1) {
    hco_server_conf *sconf = hco_get_server_conf(cmd->server);

    if (!strcasecmp(a1, "allow")) {
        sconf->auth_strategy = HCO_STRATEGY_ALLOW;
    }
    else if (!strcasecmp(a1, "pass")) {
        sconf->auth_strategy = HCO_STRATEGY_PASS;
    }
    else {
        sconf->auth_strategy = HCO_STRATEGY_DENY;
    }
    return NULL;
}

/*
 * Default Server configs
 */
static void *hco_server_config_create(apr_pool_t *p, server_rec *s)
{
    hco_server_conf *sconf = (hco_server_conf *)apr_palloc(p, sizeof(hco_server_conf));

    sconf->enabled   = HCO_DISABLED;
    sconf->end_point = NULL;
    sconf->auth_key  = NULL;
    sconf->base_path = NULL;
    sconf->auth_strategy = HCO_STRATEGY_DENY;
    return (void *)sconf;
}


static int hco_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    /*void *data;
    int first_time = 0;
    const char *userdata_key = "hco_init_module";

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "HCO: post config --checking data");
    if (!data) {

        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "HCO: post config.");
        first_time = 1;
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
*/

        int turn_off = 0;
        hco_server_conf *sconf = hco_get_server_conf(s);

        if(!sconf->enabled) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "HCO: disabled.");
            return OK;
        } else {
            if(sconf->base_path == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "HCO: missing HcoBasePath config value.");
                turn_off = 1;
            }
            if(sconf->end_point == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "HCO: missing HcoEndPoint config value.");
                turn_off = 1;
            }
            if(sconf->auth_key == NULL) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "HCO: missing HcoAuthKey config value.");
                turn_off = 1;
            }
            if(turn_off) {
                sconf->enabled= HCO_DISABLED;
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "HCO: turning off.");
                return OK;
            }
        }

        // good, we're here.
        // let's configure a cURL handler.
        curl_global_init(CURL_GLOBAL_ALL);
        sconf->curl = curl_easy_init();

        if(sconf->curl) {
            // can setup global curl options here.
            curl_easy_setopt(sconf->curl, CURLOPT_URL, sconf->end_point);
            // setup our user agent
            char *user_agent = apr_pstrcat(s->process->pool,
                "hco-agent/0.1 (+httpd: <",
                ap_get_server_description(),
                "> +apr: <",
                APR_VERSION_STRING,
                "> +libcURL: <",
                curl_version(),
                ">) build: ",
                __DATE__,
                "-",
                __TIME__,
#if APR_HAS_THREADS
                " (threaded)",
#endif
                NULL
            );
            curl_easy_setopt(sconf->curl, CURLOPT_USERAGENT, user_agent);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "HCO: %s.", user_agent);
#if 1
// XXX. replace with debug.
            curl_easy_setopt(sconf->curl, CURLOPT_HEADER, 1);
#endif
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "HCO: failed to create cURL handler.");
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "HCO: turrning off.");
            sconf->enabled = HCO_DISABLED;
        }

    //}

    // for (; s; s = s->next) {
    // }

    return OK;
}



static const command_rec hco_cmds[] =
{
    AP_INIT_FLAG("HcoEngine", cmd_hco_engine,  NULL, ACCESS_CONF,
        "On or Off to enable or disable (default) the whole hco engine"),
    AP_INIT_TAKE1("HcoBasePath", cmd_hco_base_path, NULL, ACCESS_CONF,
        "base path"),
    AP_INIT_TAKE1("HcoEndPoint", cmd_hco_end_point, NULL, ACCESS_CONF,
        "end point URL"),
    AP_INIT_TAKE1("HcoAuthKey", cmd_hco_auth_key, NULL, ACCESS_CONF,
        "provider key"),
    AP_INIT_TAKE1("HcoAuthStrategy", cmd_hco_auth_strategy, NULL, ACCESS_CONF,
        "provider key"),
    { NULL }
};

static void hco_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(hco_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(hco_fixups, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(hco_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction(hco_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA hco_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    hco_server_config_create,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    hco_cmds,                  /* table of config file commands       */
    hco_register_hooks  /* register hooks                      */
};

