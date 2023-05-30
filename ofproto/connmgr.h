/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONNMGR_H
#define CONNMGR_H 1

#include "classifier.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-connection.h"
#include "ofproto.h"
#include "ofproto-provider.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/types.h"

struct nlattr;
struct ofconn;
struct ofputil_flow_removed;
struct ofputil_requestforward;
struct rule;
struct simap;
struct sset;

void connmgr_send_anomaly_detection(struct connmgr *, struct ofpbuf *);

/* An asynchronous message that might need to be queued between threads. */
struct ofproto_async_msg {
    struct ovs_list list_node;  /* For queuing. */
    uint16_t controller_id;     /* Controller ID to send to. */

    enum ofputil_async_msg_type oam;
    /* OAM_PACKET_IN. */
    struct {
        struct ofputil_packet_in_private up;
        int max_len;            /* From action, or -1 if none. */
    } pin;
};
void ofproto_async_msg_free(struct ofproto_async_msg *);

/* Basics. */
struct connmgr *connmgr_create(struct ofproto *ofproto,
                               const char *dpif_name, const char *local_name);
void connmgr_destroy(struct connmgr *)
    OVS_REQUIRES(ofproto_mutex);

void connmgr_run(struct connmgr *,
                 void (*handle_openflow)(struct ofconn *,
                                         const struct ovs_list *msgs));
void connmgr_wait(struct connmgr *);

void connmgr_get_memory_usage(const struct connmgr *, struct simap *usage);

struct ofproto *ofconn_get_ofproto(const struct ofconn *);

void connmgr_set_bundle_idle_timeout(unsigned timeout);

void connmgr_retry(struct connmgr *);

/* OpenFlow configuration. */
bool connmgr_has_controllers(const struct connmgr *);
void connmgr_get_controller_info(struct connmgr *, struct shash *);
void connmgr_free_controller_info(struct shash *);
void connmgr_set_controllers(struct connmgr *, struct shash *);
void connmgr_reconnect(const struct connmgr *);

int connmgr_set_snoops(struct connmgr *, const struct sset *snoops);
bool connmgr_has_snoops(const struct connmgr *);
void connmgr_get_snoops(const struct connmgr *, struct sset *snoops);

/* Individual connections to OpenFlow controllers. */
enum ofconn_type ofconn_get_type(const struct ofconn *);

bool ofconn_get_primary_election_id(const struct ofconn *, uint64_t *idp);
bool ofconn_set_primary_election_id(struct ofconn *, uint64_t);
enum ofp12_controller_role ofconn_get_role(const struct ofconn *);
void ofconn_set_role(struct ofconn *, enum ofp12_controller_role);

enum ofputil_protocol ofconn_get_protocol(const struct ofconn *);
void ofconn_set_protocol(struct ofconn *, enum ofputil_protocol);

enum ofputil_packet_in_format ofconn_get_packet_in_format(struct ofconn *);
void ofconn_set_packet_in_format(struct ofconn *,
                                 enum ofputil_packet_in_format);

void ofconn_set_controller_id(struct ofconn *, uint16_t controller_id);

void ofconn_set_invalid_ttl_to_controller(struct ofconn *, bool);
bool ofconn_get_invalid_ttl_to_controller(struct ofconn *);

int ofconn_get_miss_send_len(const struct ofconn *);
void ofconn_set_miss_send_len(struct ofconn *, int miss_send_len);

void ofconn_set_async_config(struct ofconn *,
                             const struct ofputil_async_cfg *);
struct ofputil_async_cfg ofconn_get_async_config(const struct ofconn *);

void ofconn_send_reply(const struct ofconn *, struct ofpbuf *);
void ofconn_send_replies(const struct ofconn *, struct ovs_list *);
void ofconn_send_error(const struct ofconn *, const struct ofp_header *request,
                       enum ofperr);

struct ofp_bundle;

struct ofp_bundle *ofconn_get_bundle(struct ofconn *, uint32_t id);
void ofconn_insert_bundle(struct ofconn *, struct ofp_bundle *);
void ofconn_remove_bundle(struct ofconn *, struct ofp_bundle *);

/* Logging flow_mod summaries. */
void ofconn_report_flow_mod(struct ofconn *, enum ofp_flow_mod_command);

/* Sending asynchronous messages. */
bool connmgr_wants_packet_in_on_miss(struct connmgr *mgr);
void connmgr_send_port_status(struct connmgr *, struct ofconn *source,
                              const struct ofputil_phy_port *old_pp,
                              const struct ofputil_phy_port *new_pp,
                              uint8_t reason);
void connmgr_send_flow_removed(struct connmgr *,
                               const struct ofputil_flow_removed *)
    OVS_REQUIRES(ofproto_mutex);
void connmgr_send_async_msg(struct connmgr *,
                            const struct ofproto_async_msg *);
void ofconn_send_role_status(struct ofconn *ofconn, uint32_t role,
                             uint8_t reason);

void connmgr_send_requestforward(struct connmgr *, const struct ofconn *source,
                                 const struct ofputil_requestforward *);

/* Fail-open settings. */
enum ofproto_fail_mode connmgr_get_fail_mode(const struct connmgr *);
void connmgr_set_fail_mode(struct connmgr *, enum ofproto_fail_mode);

/* Fail-open implementation. */
int connmgr_get_max_probe_interval(const struct connmgr *);
bool connmgr_is_any_controller_connected(const struct connmgr *);
bool connmgr_is_any_controller_admitted(const struct connmgr *);
int connmgr_failure_duration(const struct connmgr *);

/* In-band configuration. */
void connmgr_set_extra_in_band_remotes(struct connmgr *,
                                       const struct sockaddr_in *, size_t);
void connmgr_set_in_band_queue(struct connmgr *, int queue_id);

/* In-band implementation. */
bool connmgr_has_in_band(struct connmgr *);

/* Fail-open and in-band implementation. */
void connmgr_flushed(struct connmgr *);

int connmgr_count_hidden_rules(const struct connmgr *);

/* A flow monitor managed by NXST_FLOW_MONITOR and related requests. */
struct ofmonitor {
    struct ofconn *ofconn;      /* Owning 'ofconn'. */
    struct hmap_node ofconn_node; /* In ofconn's 'monitors' hmap. */
    uint32_t id;

    enum ofp14_flow_monitor_flags flags;

    /* Matching. */
    ofp_port_t out_port;
    uint32_t out_group;
    uint8_t table_id;
    struct minimatch match;
};

struct ofputil_flow_monitor_request;

enum ofperr ofmonitor_create(const struct ofputil_flow_monitor_request *,
                             struct ofconn *, struct ofmonitor **)
    OVS_REQUIRES(ofproto_mutex);
struct ofmonitor *ofmonitor_lookup(struct ofconn *, uint32_t id)
    OVS_REQUIRES(ofproto_mutex);
void ofmonitor_destroy(struct ofmonitor *)
    OVS_REQUIRES(ofproto_mutex);

void ofmonitor_report(struct connmgr *, struct rule *,
                      enum ofp_flow_update_event event,
                      enum ofp_flow_removed_reason,
                      const struct ofconn *abbrev_ofconn, ovs_be32 abbrev_xid,
                      const struct rule_actions *old_actions)
    OVS_REQUIRES(ofproto_mutex);
void ofmonitor_flush(struct connmgr *) OVS_REQUIRES(ofproto_mutex);


struct rule_collection;
void ofmonitor_collect_resume_rules(struct ofmonitor *, uint64_t seqno,
                                    struct rule_collection *)
    OVS_REQUIRES(ofproto_mutex);
void ofmonitor_compose_refresh_updates(struct rule_collection *rules,
                                       struct ovs_list *msgs,
                                       enum ofputil_protocol protocol)
    OVS_REQUIRES(ofproto_mutex);

void connmgr_send_table_status(struct connmgr *,
                               const struct ofputil_table_desc *td,
                               uint8_t reason);

/*Hieu*/
// extern bool keepRunning;
#ifndef BARRUST_SIMPLE_COUNT_MIN_SKETCH_H__
#define BARRUST_SIMPLE_COUNT_MIN_SKETCH_H__

/*******************************************************************************
***     Author: Tyler Barrus
***     email:  barrust@gmail.com
***     Version: 0.2.0
***     License: MIT 2017
*******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>

#define COUNT_MIN_SKETCH_VERSION "0.1.8"

/*  CMS_ERROR is problematic in that it is difficult to check for the error
    state since `INT_MIN` is a valid return value of the number of items
    inserted in at the furthest point
    TODO: Consider other options for signaling error states */
#define CMS_SUCCESS  0
#define CMS_ERROR   INT32_MIN



/* https://gcc.gnu.org/onlinedocs/gcc/Alternate-Keywords.html#Alternate-Keywords */
#ifndef __GNUC__
#define __inline__ inline
#endif

/* hashing function type */
typedef uint64_t* (*cms_hash_function) (unsigned int num_hashes, const char* key);

typedef struct {
    uint32_t depth;
    uint32_t width;
    int64_t elements_added;
    double confidence;
    double error_rate;
    cms_hash_function hash_function;
    int32_t* bins;
    bool* bool_array;
    bool* bool_array2; //bool array to allow forward in OVS
}  CountMinSketch, count_min_sketch;


/*  Initialize the count-min sketch based on user defined width and depth
    Alternatively, one can also pass in a custom hash function

    Returns:
        CMS_SUCCESS
        CMS_ERROR   -   when unable to allocate the desired cms object or when width or depth are 0 */
int cms_init_alt(CountMinSketch* cms, unsigned int width, unsigned int depth, cms_hash_function hash_function);
static __inline__ int cms_init(CountMinSketch* cms, unsigned int width, unsigned int depth) {
    return cms_init_alt(cms, width, depth, NULL);
}


/*  Initialize the count-min sketch based on user defined error rate and
    confidence values which is technically the optimal setup for the users needs
    Alternatively, one can also pass in a custom hash function

    Returns:
        CMS_SUCCESS
        CMS_ERROR   -   when unable to allocate the desired cms object or when error_rate or confidence is negative */
int cms_init_optimal_alt(CountMinSketch* cms, double error_rate, double confidence, cms_hash_function hash_function);
static __inline__ int cms_init_optimal(CountMinSketch* cms, float error_rate, float confidence) {
    return cms_init_optimal_alt(cms, error_rate, confidence, NULL);
}


/*  Free all memory used in the count-min sketch

    Return:
        CMS_SUCCESS */
int cms_destroy(CountMinSketch* cms);


/*  Reset the count-min sketch to zero elements inserted

    Return:
        CMS_SUCCESS */
int cms_clear(CountMinSketch* cms);

/* Export count-min sketch to file

    Return:
        CMS_SUCCESS - When file is opened and written
        CMS_ERROR   - When file is unable to be opened */
int cms_export(CountMinSketch* cms, const char* filepath);

/*  Import count-min sketch from file

    Return:
        CMS_SUCCESS - When file is opened and written
        CMS_ERROR   - When file is unable to be opened

    NOTE: It is up to the caller to provide the correct hashing algorithm */
int cms_import_alt(CountMinSketch* cms, const char* filepath, cms_hash_function hash_function);
static __inline__ int cms_import(CountMinSketch* cms, const char* filepath) {
    return cms_import_alt(cms, filepath, NULL);
}

/*  Insertion family of functions:

    Insert the provided key or hash values into the count-min sketch X number of times.
    Possible arguments:
        key         -   The key to insert
        x           -   The number of times to insert the key; if this parameter
                        is not present in the function then it is 1
        hashes      -   A set of hashes that represent the key to insert; very
                        useful when adding the same element to many count-min
                        sketches. This is only provieded if key is not.
        num_hashes  -   The number of hashes in the hash array
    Returns:
        On Success  -   The number of times `key` or `hashes` that have been
                        inserted using `min` estimation;
                        NOTE: result can be negative!
        On Failure  -   CMS_ERROR; this happens if there is an issue with the
                        number of hashes provided.
*/

/* Add the provided key to the count-min sketch `x` times */
// int32_t cms_add_inc(CountMinSketch* cms, const char* key, uint32_t x);
bool cms_add_inc(CountMinSketch* cms, const char* key, uint32_t x);
// int32_t cms_add_inc_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes, uint32_t x);
bool cms_add_inc_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes, uint32_t x);

/* Add the provided key to the count-min sketch */
// static __inline__ int32_t cms_add(CountMinSketch* cms, const char* key) {
static __inline__ bool cms_add(CountMinSketch* cms, const char* key) {
    return cms_add_inc(cms, key, 1);
}
static __inline__ int32_t cms_add_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes) {
    return cms_add_inc_alt(cms, hashes, num_hashes, 1);
}

/*  Remove the provided key to the count-min sketch `x` times;
    NOTE: Result Values can be negative
    NOTE: Best check method when remove is used is `cms_check_mean` */
int32_t cms_remove_inc(CountMinSketch* cms, const char* key, uint32_t x);
int32_t cms_remove_inc_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes, uint32_t x);

/*  Remove the provided key to the count-min sketch;
    NOTE: Result Values can be negative
    NOTE: Best check method when remove is used is `cms_check_mean` */
static __inline__ int32_t cms_remove(CountMinSketch* cms, const char* key) {
    return cms_remove_inc(cms, key, 1);
}
static __inline__ int32_t cms_remove_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes) {
    return cms_remove_inc_alt(cms, hashes, num_hashes, 1);
}

/* Determine the maximum number of times the key may have been inserted */
// int32_t cms_check(CountMinSketch* cms, const char* key);
bool cms_check(CountMinSketch* cms, const char* key);
// int32_t cms_check_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes);
bool cms_check_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes);
// static __inline__ int32_t cms_check_min(CountMinSketch* cms, const char* key) {
static __inline__ bool cms_check_min(CountMinSketch* cms, const char* key) {
    return cms_check(cms, key);
}
static __inline__ int32_t cms_check_min_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes) {
    return cms_check_alt(cms, hashes, num_hashes);
}

/*  Determine the mean number of times the key may have been inserted
    NOTE: Mean check increases the over counting but is a `better` strategy
    when removes are added and negatives are possible */
int32_t cms_check_mean(CountMinSketch* cms, const char* key);
int32_t cms_check_mean_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes);

int32_t cms_check_mean_min(CountMinSketch* cms, const char* key);
int32_t cms_check_mean_min_alt(CountMinSketch* cms, uint64_t* hashes, unsigned int num_hashes);

/*  Return the hashes for the provided key based on the hashing function of
    the count-min sketch
    NOTE: Useful when multiple count-min sketches use the same hashing
    functions
    NOTE: Up to the caller to free the array of hash values */
uint64_t* cms_get_hashes_alt(CountMinSketch* cms, unsigned int num_hashes, const char* key);
static __inline__ uint64_t* cms_get_hashes(CountMinSketch* cms, const char* key) {
    return cms_get_hashes_alt(cms, cms->depth, key);
}

/*  Initialized count-min sketch and merge the cms' directly into the newly
    initialized object
    Return:
        CMS_SUCCESS - When all count-min sketches are of the same size, etc and
                      were successfully merged
        CMS_ERROR   - When there was an error completing the merge; including
                      when the cms' are not all of the same demensions, unable
                      to allocate the correct memory, etc.
*/
int cms_merge(CountMinSketch* cms, int num_sketches, ...);

/*  Merge the count-min sketches into a previously initlized object that may
    not be empty
    Return:
        CMS_SUCCESS - When all count-min sketches are of the same size, etc and
                      were successfully merged
        CMS_ERROR   - When there was an error completing the merge; including
                      when the cms' are not all of the same demensions, unable
                      to allocate the correct memory, etc.
*/
int cms_merge_into(CountMinSketch* cms, int num_sketches, ...);


#ifdef __cplusplus
} // extern "C"
#endif

#endif

void* funct(void *param);
extern bool keepRunning;

/*Hieu*/

#endif /* connmgr.h */
