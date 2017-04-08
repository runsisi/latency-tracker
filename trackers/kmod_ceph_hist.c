/*
 * kmod_ceph_hist.c
 *
 * Copyright (C) 2017 runsisi <runsisi@hust.edu.cn>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/cpu.h>
#include "kmod_ceph_hist.h"
#include "../latency_tracker.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"
#include "../wrapper/percpu-defs.h"
#include "../wrapper/jiffies.h"
#include "../wrapper/lt_probe.h"

#include "trace/events/latency_tracker.h"

DEFINE_PER_CPU(struct iohist, hist);

static struct proc_dir_entry *hist_proc_dentry;
static const struct file_operations hist_proc_fops;

static void update_hist(struct latency_tracker_event *ev, enum tracker_key_type t, struct iohist *h);

static int rq_cnt;
static int skip_cnt;

static struct latency_tracker *tracker;

LT_PROBE_DEFINE(rbd_img_request_submit, void *rq)
{
  struct event_key_t key;
  enum latency_tracker_event_in_ret ret;

  if (!latency_tracker_get_tracking_on(tracker))
    return;

  rq_cnt++;

  key.type = KEY_TYPE_RBD_RQ_SUBMIT;
  key.rq = rq;

  ret = latency_tracker_event_in(tracker, &key, sizeof(key), 0, NULL);
  if (ret == LATENCY_TRACKER_FULL) {
    skip_cnt++;
    printk("latency_tracker kmod-ceph: no more free events, consider "
        "increasing the max_events parameter\n");
  } else if (ret) {
    printk("latency_tracker kmod-ceph: error adding event\n");
  }
}

LT_PROBE_DEFINE(rbd_img_request_complete, void *rq)
{
  struct event_key_t key;
  struct latency_tracker_event *ev;

  if (!latency_tracker_get_tracking_on(tracker))
    return;

  key.type = KEY_TYPE_RBD_RQ_SUBMIT;
  key.rq = rq;

  ev = latency_tracker_get_event_by_key(tracker, &key, sizeof(key), NULL);
  if (!ev)
    goto end;

  update_hist(ev, KEY_TYPE_RBD_RQ_SUBMIT, lttng_this_cpu_ptr(&hist));

  latency_tracker_unref_event(ev);

end:
  latency_tracker_event_out(tracker, NULL, &key, sizeof(key), 0, 0);
  return;
}

LT_PROBE_DEFINE(osd_client_submit_request, void *rq)
{
  struct event_key_t key;
  enum latency_tracker_event_in_ret ret;

  if (!latency_tracker_get_tracking_on(tracker))
    return;

  rq_cnt++;

  key.type = KEY_TYPE_OSD_RQ_SUBMIT;
  key.rq = rq;

  ret = latency_tracker_event_in(tracker, &key, sizeof(key), 0, NULL);
  if (ret == LATENCY_TRACKER_FULL) {
    skip_cnt++;
    printk("latency_tracker kmod-ceph: no more free events, consider "
        "increasing the max_events parameter\n");
  } else if (ret) {
    printk("latency_tracker kmod-ceph: error adding event\n");
  }
}

LT_PROBE_DEFINE(osd_client_complete_request, void *rq)
{
  struct event_key_t key;
  struct latency_tracker_event *ev;

  if (!latency_tracker_get_tracking_on(tracker))
    return;

  key.type = KEY_TYPE_OSD_RQ_SUBMIT;
  key.rq = rq;

  ev = latency_tracker_get_event_by_key(tracker, &key, sizeof(key), NULL);
  if (!ev)
    goto end;

  update_hist(ev, KEY_TYPE_OSD_RQ_SUBMIT, lttng_this_cpu_ptr(&hist));

  latency_tracker_unref_event(ev);

end:
  latency_tracker_event_out(tracker, NULL, &key, sizeof(key), 0, 0);
  return;
}

LT_PROBE_DEFINE(osd_client_send_request, uint64_t tid)
{
  struct event_key_t key;
  enum latency_tracker_event_in_ret ret;

  if (!latency_tracker_get_tracking_on(tracker))
    return;

  rq_cnt++;

  key.type = KEY_TYPE_OSD_RQ_SEND;
  key.tid = tid;

  ret = latency_tracker_event_in(tracker, &key, sizeof(key), 0, NULL);
  if (ret == LATENCY_TRACKER_FULL) {
    skip_cnt++;
    printk("latency_tracker kmod-ceph: no more free events, consider "
        "increasing the max_events parameter\n");
  } else if (ret) {
    printk("latency_tracker kmod-ceph: error adding event\n");
  }
}

LT_PROBE_DEFINE(osd_client_handle_reply, uint64_t tid)
{
  struct event_key_t key;
  struct latency_tracker_event *ev;

  if (!latency_tracker_get_tracking_on(tracker))
    return;

  key.type = KEY_TYPE_OSD_RQ_SEND;
  key.tid = tid;

  ev = latency_tracker_get_event_by_key(tracker, &key, sizeof(key), NULL);
  if (!ev)
    goto end;

  update_hist(ev, KEY_TYPE_OSD_RQ_SEND, lttng_this_cpu_ptr(&hist));

  latency_tracker_unref_event(ev);

end:
  latency_tracker_event_out(tracker, NULL, &key, sizeof(key), 0, 0);
  return;
}

static
unsigned int get_bucket(uint64_t v)
{
  if (v > (1ULL << (LATENCY_BUCKETS - 1)))
    return LATENCY_BUCKETS;
  return fls_long(v - 1) - 1;
}

static
void output_bucket_value(uint64_t v, struct seq_file *m)
{
  if (v > (1ULL << 29))
    seq_printf(m, "%llus", v >> 30);
  else if (v > (1ULL << 19))
    seq_printf(m, "%llums", v >> 20);
  else if (v > (1ULL << 9))
    seq_printf(m, "%lluus", v >> 10);
  else
    seq_printf(m, "%lluns", v);
}

void update_hist(struct latency_tracker_event *ev, enum tracker_key_type t, struct iohist *h)
{
  u64 now, delta;
  int bucket;
  unsigned long flags;

  now = trace_clock_read64();
  delta = now - latency_tracker_event_get_start_ts(ev);

  spin_lock_irqsave(&h->lock, flags);
  if (delta < h->mins[t])
    h->mins[t] = delta;
  if (delta > h->maxs[t])
    h->maxs[t] = delta;
  h->sums[t] += delta;

  bucket = get_bucket(delta);
  h->nrs[t][bucket]++;
  spin_unlock_irqrestore(&h->lock, flags);
}

static
void merge_per_cpu_hist(struct iohist *h)
{
  int cpu, i, j;
  struct iohist *c;
  unsigned long flags;

  memset(h, 0, sizeof(*h));
  for (i = 0; i < KEY_TYPE_NR; i++) {
    h->mins[i] = -1ULL;
    h->maxs[i] = 0;
    h->sums[i] = 0;
  }

  get_online_cpus();
  for_each_online_cpu(cpu) {
    c = per_cpu_ptr(&hist, cpu);
    spin_lock_irqsave(&c->lock, flags);
    for (i = 0; i < KEY_TYPE_NR; i++) {
      if (c->mins[i] < h->mins[i])
        h->mins[i] = c->mins[i];
      if (c->maxs[i] > h->maxs[i])
        h->maxs[i] = c->maxs[i];
      h->sums[i] += c->sums[i];
      for (j = 0; j < LATENCY_BUCKETS; j++) {
        h->nrs[i][j] += c->nrs[i][j];
      }
    }
    spin_unlock_irqrestore(&c->lock, flags);
  }
  put_online_cpus();

  for (i = 0; i < KEY_TYPE_NR; i++) {
    if (h->mins[i] == -1ULL)
      h->mins[i] = 0;
  }
}

static
void reset_per_cpu_hist(void)
{
  int cpu, i, j;
  struct iohist *c;
  unsigned long flags;

  get_online_cpus();
  for_each_online_cpu(cpu) {
    c = per_cpu_ptr(&hist, cpu);
    spin_lock_irqsave(&c->lock, flags);
    for (i = 0; i < KEY_TYPE_NR; i++) {
      c->mins[i] = -1ULL;
      c->maxs[i] = 0;
      c->sums[i] = 0;
      for (j = 0; j < LATENCY_BUCKETS; j++) {
        c->nrs[i][j] = 0;
      }
    }
    spin_unlock_irqrestore(&c->lock, flags);
  }
  put_online_cpus();
}

static
int calc_percent(uint64_t a, uint64_t b)
{
  if (b == 0)
    return 0;
  return a * 100 / b;
}

static
int output_hist(struct seq_file *m, void *v)
{
  struct iohist h;
  int i, j;

  uint64_t nrs[KEY_TYPE_NR];
  uint64_t nrs_for_div[KEY_TYPE_NR];
  uint64_t avgs[KEY_TYPE_NR];

  merge_per_cpu_hist(&h);

  for (i = 0; i < KEY_TYPE_NR; i++) {
    nrs[i] = 0;
    avgs[i] = 0;

    for (j = 0; j < LATENCY_BUCKETS; j++) {
      nrs[i] += h.nrs[i][j];
    }

    if (nrs[i] == 0) {
      h.sums[i] = 0;
      nrs_for_div[i] = 1;
    }

    avgs[i] = h.sums[i] / nrs_for_div[i];
  }

  seq_printf(m, "Latency range\t\t|RBD rq submit(%%)\t|OSD rq submit(%%)\t"
      "|OSD rq send(%%)\n");
  seq_printf(m, "#############################################################"
      "##########################");
  for (i = 0; i < LATENCY_BUCKETS - 1; i++) {
    seq_printf(m, "\n[");
    output_bucket_value(1ULL << i, m);
    seq_printf(m, ",\t");
    output_bucket_value(1ULL << (i + 1), m);
    seq_printf(m, "\t]");
    seq_printf(m, "\t %d\t\t", calc_percent(h.nrs[KEY_TYPE_RBD_RQ_SUBMIT][i], nrs[KEY_TYPE_RBD_RQ_SUBMIT]));
    seq_printf(m, "\t %d\t\t", calc_percent(h.nrs[KEY_TYPE_OSD_RQ_SUBMIT][i], nrs[KEY_TYPE_OSD_RQ_SUBMIT]));
    seq_printf(m, "\t %d", calc_percent(h.nrs[KEY_TYPE_OSD_RQ_SEND][i], nrs[KEY_TYPE_OSD_RQ_SEND]));
  }
  {
    seq_printf(m, "\n[");
    output_bucket_value(1ULL << i, m);
    seq_printf(m, ",\t");
    seq_printf(m, "...");
    seq_printf(m, "\t]");
    seq_printf(m, "\t %d\t\t", calc_percent(h.nrs[KEY_TYPE_RBD_RQ_SUBMIT][i], nrs[KEY_TYPE_RBD_RQ_SUBMIT]));
    seq_printf(m, "\t %d\t\t", calc_percent(h.nrs[KEY_TYPE_OSD_RQ_SUBMIT][i], nrs[KEY_TYPE_OSD_RQ_SUBMIT]));
    seq_printf(m, "\t %d", calc_percent(h.nrs[KEY_TYPE_OSD_RQ_SEND][i], nrs[KEY_TYPE_OSD_RQ_SEND]));
  }
  seq_printf(m, "\n\n");
  seq_printf(m, "#############################################################"
      "##########################\n");

  /* total nr           33      44 */
  /* min latency        1       2 */
  /* max latency        44      55 */
  /* avg latency        11      22 */
  seq_printf(m, "total nr.\t\t %llu\t\t\t %llu\t\t\t %llu\n",
      nrs[KEY_TYPE_RBD_RQ_SUBMIT], nrs[KEY_TYPE_OSD_RQ_SUBMIT], nrs[KEY_TYPE_OSD_RQ_SEND]);
  seq_printf(m, "min latency\t\t %llu\t\t\t %llu\t\t\t %llu\n",
      h.mins[KEY_TYPE_RBD_RQ_SUBMIT], h.mins[KEY_TYPE_OSD_RQ_SUBMIT], h.mins[KEY_TYPE_OSD_RQ_SEND]);
  seq_printf(m, "max latency\t\t %llu\t\t\t %llu\t\t\t %llu\n",
      h.maxs[KEY_TYPE_RBD_RQ_SUBMIT], h.maxs[KEY_TYPE_OSD_RQ_SUBMIT], h.maxs[KEY_TYPE_OSD_RQ_SEND]);
  seq_printf(m, "avg latency\t\t %llu\t\t\t %llu\t\t\t %llu\n",
      avgs[KEY_TYPE_RBD_RQ_SUBMIT], avgs[KEY_TYPE_OSD_RQ_SUBMIT], avgs[KEY_TYPE_OSD_RQ_SEND]);
  return 0;
}

static
int tracker_proc_open(struct inode *inode, struct file *filp)
{
  return single_open(filp, output_hist, NULL);
}

static
ssize_t tracker_proc_write(struct file *filp, const char __user *buf, size_t count, loff_t *offp)
{
  reset_per_cpu_hist();
  return count;
}

static const struct file_operations hist_proc_fops =
{ .owner = THIS_MODULE, .open = tracker_proc_open, .read = seq_read, .write = tracker_proc_write,
    .llseek = seq_lseek, .release = single_release, };

static
void init_histograms(void)
{
  int cpu, i, j;
  struct iohist *c;

  for_each_possible_cpu(cpu) {
    c = per_cpu_ptr(&hist, cpu);
    spin_lock_init(&c->lock);
    for (i = 0; i < KEY_TYPE_NR; i++) {
      c->mins[i] = -1ULL;
      c->maxs[i] = 0;
      c->sums[i] = 0;
      for (j = 0; j < LATENCY_BUCKETS; j++) {
        c->nrs[i][j] = 0;
      }
    }
  }
}

static
int __init kmod_ceph_hist_tracker_init(void)
{
  int ret;

  rq_cnt = skip_cnt = 0;

  tracker = latency_tracker_create("kmod_ceph_hist");
  if (!tracker)
    goto error;

  latency_tracker_set_threshold(tracker, 0);
  latency_tracker_set_startup_events(tracker, 256);
  latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);

  init_histograms();

  ret = lttng_wrapper_tracepoint_probe_register("rbd_img_request_submit",
      probe_rbd_img_request_submit, NULL);
  WARN_ON(ret);

  ret = lttng_wrapper_tracepoint_probe_register("rbd_img_request_complete",
      probe_rbd_img_request_complete, NULL);
  WARN_ON(ret);

  ret = lttng_wrapper_tracepoint_probe_register("osd_client_submit_request",
      probe_osd_client_submit_request, NULL);
  WARN_ON(ret);

  ret = lttng_wrapper_tracepoint_probe_register("osd_client_complete_request",
      probe_osd_client_complete_request, NULL);
  WARN_ON(ret);

  ret = lttng_wrapper_tracepoint_probe_register("osd_client_send_request",
      probe_osd_client_send_request, NULL);
  WARN_ON(ret);

  ret = lttng_wrapper_tracepoint_probe_register("osd_client_handle_reply",
      probe_osd_client_handle_reply, NULL);
  WARN_ON(ret);

  hist_proc_dentry = proc_create("kmod_ceph_hist",
      0, NULL, &hist_proc_fops);

  if (!hist_proc_dentry) {
    printk(KERN_ERR "Error creating tracker control file\n");
    ret = -ENOMEM;
    goto end;
  }

  ret = 0;
  goto end;

error:
  ret = -1;
end:
  return ret;
}
module_init( kmod_ceph_hist_tracker_init);

static
void __exit kmod_ceph_hist_tracker_exit(void)
{
  lttng_wrapper_tracepoint_probe_unregister("rbd_img_request_submit",
      probe_rbd_img_request_submit, NULL);
  lttng_wrapper_tracepoint_probe_unregister("rbd_img_request_complete",
      probe_rbd_img_request_complete, NULL);
  lttng_wrapper_tracepoint_probe_unregister("osd_client_submit_request",
      probe_osd_client_submit_request, NULL);
  lttng_wrapper_tracepoint_probe_unregister("osd_client_complete_request",
      probe_osd_client_complete_request, NULL);
  lttng_wrapper_tracepoint_probe_unregister("osd_client_send_request",
      probe_osd_client_send_request, NULL);
  lttng_wrapper_tracepoint_probe_unregister("osd_client_handle_reply",
      probe_osd_client_handle_reply, NULL);

  tracepoint_synchronize_unregister();

  latency_tracker_destroy(tracker);

  if (hist_proc_dentry)
  remove_proc_entry("kmod_ceph_hist", NULL);

  printk("Total block requests : %d\n", rq_cnt);
  printk("Skipped : %d\n", skip_cnt);
}
module_exit( kmod_ceph_hist_tracker_exit);

MODULE_AUTHOR("runsisi <runsisi@hust.edu.cn>");
MODULE_LICENSE("GPL and additional rights");
MODULE_VERSION("1.0");
