#ifndef _TP_KMOD_CEPH_HIST_H
#define _TP_KMOD_CEPH_HIST_H

/*
 * kmod_ceph_hist.h
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

#include "../latency_tracker.h"

/*
 * log2 scale, so:
 * 0-9:   1ns, 2, 4, 8, 16, 32, 64, 128, 256, 512
 * 10-19: 1us, 2, 4...
 * 20-29: 1ms, ... 512ms
 * 30: > 1s
 * = 31 intervals
 */
#define LATENCY_BUCKETS 31

enum tracker_key_type {
  KEY_TYPE_RBD_RQ_SUBMIT = 0,
  KEY_TYPE_OSD_RQ_SUBMIT = 1,
  KEY_TYPE_OSD_RQ_SEND = 2,
  KEY_TYPE_NR
};

struct event_key_t {
  enum tracker_key_type type;
  union {
    void *rq;
    uint64_t tid;
  };
} __attribute__((__packed__));

/* Update this with the biggest key struct */
#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(struct event_key_t)

struct iohist {
  // for per cpu locking
  spinlock_t lock;
  uint64_t mins[KEY_TYPE_NR];
  uint64_t maxs[KEY_TYPE_NR];
  uint64_t sums[KEY_TYPE_NR];
  uint64_t nrs[KEY_TYPE_NR][LATENCY_BUCKETS];
};

#endif /* _TP_KMOD_CEPH_HIST_H */
